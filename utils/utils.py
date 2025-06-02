import os
import re
import subprocess
import hashlib
import frida
from elftools.elf.elffile import ELFFile
from colorist import ColorRGB
import math

def worker_color(worker_nr, nr_devices):
    r, g, b = thread_num2rgb(worker_nr, nr_devices)
    return ColorRGB(r, b, g)


def thread_num2rgb(val, max_val):
    i = val * 255 / max_val
    r = round(math.sin(0.024 * i + 0) * 127 + 128)
    g = round(math.sin(0.024 * i + 2) * 127 + 128)
    b = round(math.sin(0.024 * i + 4) * 127 + 128)
    return (r, g, b)


class ProcMap:
    def __init__(self, vmas) -> None:
        self.vmas = vmas

    def get_vmabyname(self, vma_name):
        for vma in self.vmas:
            if vma.vma_name is None:
                continue
            if vma_name in vma.vma_name:
                return vma
        return None

    def get_vmabyaddr(self, addr):
        for vma in self.vmas:
            if addr <= vma.end and addr >= vma.base:
                return vma
        return None

    def get_vmaaddroff(self, addr):
        vma = self.get_vmabyaddr(addr)
        print(hex(addr), hex(vma.base))
        return addr - vma.base


class PocMap_VMA:
    def __init__(self, base, end, vma_name) -> None:
        self.base = base
        self.end = end
        self.vma_name = vma_name


def onTransact_dump_libs(onTransact_bin):
    if not os.path.exists(onTransact_bin):
        return []
    lines = open(onTransact_bin).read().split("\n")
    out = []
    for l in lines:
        if len(l.split('\t')) < 3:
            continue
        vtable_off, offset, library = l.split('\t')
        out.append(library) 
    return out

def parse_proc_maps(proc_maps_str):
    vma_list = []
    prev_vma = None  # Keep track of the previous VMA
    for line in proc_maps_str.split("\n"):
        fields = re.split(r"\s+", line.strip())
        if len(fields) < 5:
            break
        address_range = fields[0]
        permissions = fields[1]
        offset = fields[2]
        device = fields[3]
        inode = fields[4] if len(fields) == 6 else None
        pathname = fields[-1] if len(fields) > 5 else None

        # Parse the address range into base and top addresses
        base_address, top_address = map(
            lambda x: int(x, 16), address_range.split("-")
        )

        # Check if the current VMA is consecutive to the previous one
        if (
            (
            prev_vma
            #and base_address == prev_vma["top_address"]
            and pathname == prev_vma["pathname"]
            )
            #handle case for library padding..
            or
            (
            prev_vma
            and 
            permissions == '---p'
            )
        ):
            # Merge the consecutive VMAs
            prev_vma["top_address"] = top_address
        else:
            # Create a new entry for the non-consecutive VMA
            vma_info = {
                "base_address": base_address,
                "top_address": top_address,
                "permissions": permissions,
                "offset": int(offset, 16),
                "device": device,
                "inode": int(inode) if inode else None,
                "pathname": pathname,
            }

            vma_list.append(vma_info)
            prev_vma = vma_info

    out = []
    for vma in vma_list:
        out.append(
            PocMap_VMA(vma["base_address"], vma["top_address"], vma["pathname"])
        )

    return ProcMap(out)


def demangle_cpp(name):
    demangled = (
        subprocess.check_output(f"c++filt -p {name}", shell=True)
        .decode()
        .strip("\n")
    )
    return demangled


def get_libs(elf_path: str):
    imported_libraries = []
    with open(elf_path, "rb") as f:
        elffile = ELFFile(f)
        for section in elffile.iter_sections():
            if section.name == ".dynamic":
                for tag in section.iter_tags():
                    if tag.entry.d_tag == "DT_NEEDED":
                        imported_libraries.append(tag.needed)
    return imported_libraries


def remove_blocklist(libs, blocklist):
    for toblock in blocklist:
        if toblock in libs:
            libs.remove(toblock)
    return libs


def get_md5(file_path):
    # Initialize the MD5 hash object
    md5_hash = hashlib.md5()

    # Open the file in binary mode
    with open(file_path, "rb") as f:
        # Read the file in chunks
        for chunk in iter(lambda: f.read(4096), b""):
            md5_hash.update(chunk)

    # Return the hexadecimal MD5 checksum
    return md5_hash.hexdigest()


def md5sum(data: bytes) -> str:
    # Create an md5 hash object
    md5_hash = hashlib.md5()
    # Update the hash object with the data
    md5_hash.update(data)
    # Return the hexadecimal representation of the hash
    return md5_hash.hexdigest()

def get_sha1(file_path):
    """
    Compute the SHA-1 checksum of a file.
    :param file_path: Path to the file.
    :return: Hexadecimal SHA-1 checksum as a string.
    """
    # Initialize the SHA-1 hash object
    sha1_hash = hashlib.sha1()

    # Open the file in binary mode
    with open(file_path, "rb") as f:
        # Read the file in chunks
        for chunk in iter(lambda: f.read(4096), b""):
            sha1_hash.update(chunk)

    # Return the hexadecimal SHA-1 checksum
    return sha1_hash.hexdigest()

def sha1sum(data: bytes) -> str:
    """
    Compute the SHA-1 checksum of a bytes object.
    :param data: Bytes object to hash.
    :return: Hexadecimal SHA-1 checksum as a string.
    """
    # Create a SHA-1 hash object
    sha1_hash = hashlib.sha1()
    # Update the hash object with the data
    sha1_hash.update(data)
    # Return the hexadecimal representation of the hash
    return sha1_hash.hexdigest()

def extract_parcel_deserializations(binary_path):
    # return [(mangled, demangled, function name)]
    # of the binder functions in a given binary
    symbols = (
        subprocess.check_output(f"objdump -T {binary_path}", shell=True)
        .decode()
        .split("\n")
    )
    symbols = [k.split(" ")[-1] for k in symbols]
    found = []
    for s in symbols:
        if ("_ZNK7android6Parcel" in s and "read" in s) or "AParcel_read" in s:
            if s in found:
                continue
            demangled = demangle_cpp(s)
            func_name = demangled.split("::")[-1]
            found.append((s, demangled, func_name))
    return found


def renew_frida_device(device_id):
    devices = frida.enumerate_devices()
    possible_devices = [d for d in devices if d.type == "usb"]
    possible_devices = [
        d for d in possible_devices if not "ios" in d.name.lower()
    ]
    possible_devices = [d for d in possible_devices if d.id == device_id]
    if len(possible_devices) == 0:
        print(f"frida device not found...")
        return None
    elif len(possible_devices) == 1:
        device = possible_devices[0]
        return device
    else:
        return None


def find_binder_func(binder_funcs, name):
    for t, l in binder_funcs.items():
        for f in l:
            if f == name:
                return t
    return None


def get_files_in_dir(path):
    out = []
    for root, dirs, files in os.walk(path):
        for file in files:
            f = os.path.join(root, file)
            out.append(f)
    return out


def get_frida_bin(arch, version, frida_dir):
    for f in os.listdir(frida_dir):
        if arch in f and version in f:
            return f
    return None



