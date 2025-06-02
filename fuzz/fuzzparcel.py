import sys
import os
from enum import Enum
from ctypes import Structure, POINTER, c_uint, c_ubyte, c_size_t, c_void_p, CDLL, c_char_p, c_int, cast

BASE_DIR = os.path.dirname(__file__)
#LIB = CDLL(os.path.join(BASE_DIR, 'fuzzparcel_lib', 'fuzzparcel.so'))
MAX_ENTRIES = 20

class ParcelData(Structure):
    _fields_ = [
        ("type", c_uint),
        ("buf", POINTER(c_ubyte)),
        ("buf_size", c_uint)
    ]

class FuzzParcel(Structure):
    _fields_ = [
        ("code", c_uint),
        ("nr_entries", c_uint),
        ("buf", POINTER(c_ubyte)),
        ("buf_size", c_uint),
        ("index", c_uint),
        ("entries", POINTER(POINTER(ParcelData)) * MAX_ENTRIES)
    ]
"""
LIB.init_fuzzparcel.argtypes = [POINTER(c_ubyte), c_size_t]
LIB.init_fuzzparcel.restype = POINTER(FuzzParcel)

LIB.deserialize_fuzzparcel.argtypes = [POINTER(FuzzParcel)]
LIB.deserialize_fuzzparcel.restype = c_uint

LIB.print_info.argtypes = [POINTER(c_ubyte), c_size_t]
LIB.print_info.restype = None

def native_print_info(path):
    data = open(path, "rb").read()
    array_type = c_ubyte * len(data)  # Create a c_ubyte array type
    ctypes_array = array_type(*data)  # Initialize the array with the bytes data
    ctypes_pointer = cast(ctypes_array, POINTER(c_ubyte))
    inp = LIB.init_fuzzparcel(ctypes_pointer, len(data))
    LIB.deserialize_fuzzparcel(inp)
    LIB.print_info(ctypes_pointer, len(data))
"""


class ParcelType(Enum):
    BOOL = 0
    BYTE = 1
    CHAR = 2
    INT32 = 3
    INT64 = 4
    CSTRING = 5
    STRING8 = 6
    STRING16 = 7
    STRING16UTF8 = 8
    BYTEARRAY = 9
    UNKNOWN = 10
    STRONGBINDER = 11
    BOOLVECTOR = 12
    CHARVECTOR = 13
    INT32VECTOR = 14
    INT64VECTOR = 15
    STRING16VECTOR = 16
    STRING16UTF8VECTOR = 17
    FILEDESCRIPTOR = 18
    INT32PARCEABLEARRAYLEN = 19
    PARCELFILEDESCRIPTOR = 20

int_types = [
    ParcelType.CHAR,
    ParcelType.INT32,
    ParcelType.INT64,
    ParcelType.INT32PARCEABLEARRAYLEN
]

string_types = [
    ParcelType.CSTRING,
    ParcelType.STRING8,
    ParcelType.STRING16,
    ParcelType.STRING16UTF8
]

fixed_length = {
    ParcelType.BOOL: 1,
    ParcelType.BYTE: 1,
    ParcelType.CHAR: 2,
    ParcelType.INT32: 4,
    ParcelType.INT64: 8,
    ParcelType.INT32PARCEABLEARRAYLEN: 4
}

var_length = [
    ParcelType.CSTRING, 
    ParcelType.STRING8,
    ParcelType.STRING16,
    ParcelType.STRING16UTF8,
    ParcelType.BYTEARRAY,
    ParcelType.UNKNOWN,
    ParcelType.FILEDESCRIPTOR,
    ParcelType.PARCELFILEDESCRIPTOR
]

array_type = [
    ParcelType.BOOLVECTOR,
    ParcelType.CHARVECTOR,
    ParcelType.INT32VECTOR,
    ParcelType.INT64VECTOR,
]

array_type_var_length = [
    ParcelType.STRING16VECTOR,
    ParcelType.STRING16UTF8VECTOR
]

arr_type_size = {
    ParcelType.BOOLVECTOR: 1,
    ParcelType.CHARVECTOR: 2,
    ParcelType.INT32VECTOR: 4,
    ParcelType.INT64VECTOR: 8 
}

parcelfunc2type = {
    "readBool": ParcelType.BOOL,
    "readByte": ParcelType.BYTE,
    "readChar": ParcelType.CHAR,
    "readInt32": ParcelType.INT32,
    "readInt64": ParcelType.INT64,
    "readCString": ParcelType.CSTRING,
    "readString8": ParcelType.STRING8,
    "readString16": ParcelType.STRING16,
    "readUtf8FromUtf16": ParcelType.STRING16UTF8,
    "readByteArray": ParcelType.BYTEARRAY,
    "read": ParcelType.UNKNOWN, 
    "unknown": ParcelType.UNKNOWN,  
    "readStrongBinder": ParcelType.STRONGBINDER, 
    "readNativeHandle": ParcelType.BYTEARRAY, #TODO add support
    "readBoolVector": ParcelType.BOOLVECTOR,
    "readByteVector": ParcelType.BYTEARRAY,
    "readCharVector": ParcelType.CHARVECTOR,
    "readInt32Vector": ParcelType.INT32VECTOR,
    "readInt64Vector": ParcelType.INT64VECTOR,
    "readString16Vector": ParcelType.STRING16VECTOR,
    "readUtf8VectorFromUtf16Vector": ParcelType.STRING16UTF8VECTOR,
    "readFileDescriptor": ParcelType.FILEDESCRIPTOR,
    "readParcelFileDescriptor": ParcelType.PARCELFILEDESCRIPTOR, 
    "readInt32ParcebleSize": ParcelType.INT32PARCEABLEARRAYLEN
}

class FuzzParcel:
    def __init__(self, code, nr_entries, file_path=None) -> None:
        self.code = code
        self.nr_entries = nr_entries
        self.entries = []
        self.file_path = file_path
        self.remote_path = None
    def same_command(self, other):
        if self.code != other.code:
            return False
        else:
            return True
    def same_structure(self, other):
        if not self.same_command(other):
            return False 
        if self.nr_entries != other.nr_entries:
            return False
        for own_entry, other_entry in zip(self.entries, other.entries):
            if not own_entry.same_arg(other_entry):
                return False
        return True
    def to_bytes(self):
        assert self.nr_entries == len(self.entries), "mismatch between nr_entries and self.entries"
        out = b""
        out += self.code.to_bytes(4, "little")
        out += self.nr_entries.to_bytes(4, "little")
        for e in self.entries:
            out += e.to_bytes()
        return out
    def __hash__(self):
        data = str(self.code) + str(self.nr_entries)
        for entry in self.entries:
            data += str(entry)
        return hash(data)
    def __str__(self):
        out = f'FuzzParcel(code:{self.code}, nr_entries:{self.nr_entries}'
        if self.file_path is not None:
            out += f'file: {os.path.basename(self.file_path)}'
        return out
    def __repr__(self):
        out = f'FuzzParcel(code:{self.code}, nr_entries:{self.nr_entries})'
        if self.file_path is not None:
            out += f'file: {os.path.basename(self.file_path)}'
        return out
    def __eq__(self, other):
        return self.__hash__() == other.__hash__()

class ParcelEntry:
    def __init__(self, argtype, size, data):
        self.argtype = argtype
        self.size = size
        self.data = data
    def to_bytes(self):
        assert self.size != 0, "lenght is 0!!!"
        out = b""
        out += self.argtype.value.to_bytes(4, "little")
        out += self.size.to_bytes(4, "little")
        out += self.data
        return out
    def same_arg(self, other):
        return self.argtype == other.argtype and self.size == other.size
    def serialize(self):
        out = b""
    def __hash__(self):
        data = self.argtype.name.encode() + str(self.size).encode()
        data += self.data
        return hash(data)
    def __str__(self):
        return f'ParcelEntry({self.argtype.name}, {self.size}, {self.data.hex()})'
    def __repr__(self):
        return f'ParcelEntry({self.argtype.name}, {self.size}, {self.data.hex()})'
    def __eq__(self, other):
        print(self.__hash__(), other.__hash__())
        return self.__hash__() == other.__hash__()

class StrongBinderEntry():
    def __init__(self, interface_name, reply_data) -> None:
        self.interface_name = interface_name
        self.reply_data = reply_data
    def to_parcel_entry(self):
        data = (len(self.interface_name)).to_bytes(4, "little")
        data += (len(self.reply_data)).to_bytes(4, "little")
        data += self.interface_name
        data += self.reply_data
        length = len(data)
        return ParcelEntry(ParcelType.STRONGBINDER, length, data)

class ArrayVarLengthEntry():
    def __init__(self, ptype: ParcelType, entries: list[bytes]):
        self.arr_size = len(entries)
        self.entries = entries
        self.ptype = ptype
    def to_parcel_entry(self):
        data = (self.arr_size).to_bytes(4, "little")
        data += sum(len(e) for e in self.entries).to_bytes(4, "little")
        for entry in self.entries:
            data += (len(entry)).to_bytes(4, "little")
            data += entry
        length = len(data)
        return ParcelEntry(self.ptype, length, data)

def deserialize_parcel(raw_data:bytes):
    if(len(raw_data) < 8):
        print("input too small")
        return None
    off = 0
    code = int.from_bytes(raw_data[off:off+4], "little")
    off += 4
    nr_entries = int.from_bytes(raw_data[off:off+4], "little")
    off += 4
    parcel = FuzzParcel(code, nr_entries)
    for i in range(0, nr_entries):
        argtype = ParcelType(int.from_bytes(raw_data[off:off+4], "little"))
        off += 4
        size = int.from_bytes(raw_data[off:off+4], "little")
        off += 4
        data = raw_data[off:off+size]
        off += size
        parcel.entries.append(ParcelEntry(argtype, size, data))
    return parcel

def print_info(parcel:FuzzParcel):
    print(f'command code: {parcel.code}, nr_entries: {parcel.nr_entries}')
    for e in parcel.entries:
        #TODO: custom print for strongbinder
        print(f'arg {e.argtype.name}, size {e.size}, data {e.data.hex()}')

def py_print_info(path):
    data = open(path, "rb").read()
    p = deserialize_parcel(data)
    if p is None:
        return
    print_info(p) 

if __name__ == "__main__":

    if len(sys.argv) > 1:
        path = sys.argv[1]
        if os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                for file in files:
                    f = os.path.join(root, file)
                    print(f)
                    py_print_info(f)
                    #native_print_info(f)
        else:
            py_print_info(sys.argv[1]) 
            #native_print_info(sys.argv[1])

    else:

        testcases = [
            "/home/philipp/binderfuzz/binderfuzz/targets/a497c295/vendor.oplus.hardware.performance.IPerformance/default/fuzz_out/deduplicated/0/crash-2f05c91966687e9d37ece4d44caae89985ed85ad",
        ]

        for f in os.listdir("../targets/bai7gujvtchqeaus/android.os.UpdateEngineService/fuzz_out/1525_10_06_2024/data"):
            testcases.append(os.path.join("../targets/bai7gujvtchqeaus/android.os.UpdateEngineService/fuzz_out/1525_10_06_2024/data", f)) 

        for f in os.listdir("../targets/a497c295/vendor.oplus.hardware.subsys_interface.subsys_radio.ISubsysRadio/slot2/fuzz_out/1110_11_06_2024/data"):
            testcases.append(os.path.join("../targets/a497c295/vendor.oplus.hardware.subsys_interface.subsys_radio.ISubsysRadio/slot2/fuzz_out/1110_11_06_2024/data", f))

        for f in os.listdir("../targets/RZCX312P76A/vendor.samsung.hardware.radio.network.ISehRadioNetwork/slot2/fuzz_out/1910_11_06_2024/data"):
            testcases.append(os.path.join("../targets/RZCX312P76A/vendor.samsung.hardware.radio.network.ISehRadioNetwork/slot2/fuzz_out/1910_11_06_2024/data", f))


        tempfile = "/tmp/wow"
        for t in testcases:
            print(t)
            print(8*"="+"py fuzzparcel")
            py_print_info(t)
            print(8*"="+"native fuzzparcel")
            data = open(t, "rb").read()
            p = deserialize_parcel(data)
            if p.to_bytes() != open(t, "rb").read():
                print("not equal???", p, t)
                exit(-1)

            
