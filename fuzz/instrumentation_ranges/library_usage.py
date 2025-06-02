import frida 
import argparse
import os
import logging 
import traceback
import sys
from datetime import datetime
import time
import json
import tempfile
from elftools.elf.elffile import ELFFile

def get_libs(elf_path):
    imported_libraries = []
    with open(elf_path, 'rb') as f:
        elffile = ELFFile(f)
        for section in elffile.iter_sections():
            if section.name == '.dynamic':
                for tag in section.iter_tags():
                    if tag.entry.d_tag == 'DT_NEEDED':
                        imported_libraries.append(tag.needed)
    print(f'get_libs: {elf_path}: {imported_libraries}')
    return imported_libraries


base_path = os.path.dirname(__file__)
sys.path.append(os.path.join(base_path, ".."))

CUTOFF = 10

bin2ctr = {}
lib2device = {}

SERVICES = os.path.join(base_path, "..", "..", "targets")

for device in os.listdir(SERVICES):
    device_path = os.path.join(SERVICES, device)
    if not os.path.isdir(device_path):
        continue
    for service in os.listdir(device_path):
        service_path = os.path.join(device_path, service)
        if not os.path.isdir(service_path):
            continue
        if len(os.listdir(service_path)) == 1 and os.listdir(service_path)[0] == "default":
            service_path = os.path.join(service_path, "default")
        for bin in os.listdir(service_path):
            bin_path = os.path.join(service_path, bin)
            if os.path.isdir(bin_path):
                continue
            libs = get_libs(bin_path) 
            for lib in libs:
                if lib in bin2ctr:
                    bin2ctr[lib] += 1
                else:
                    bin2ctr[lib] = 1
                if lib in lib2device:
                    if device not in lib2device[lib]:
                        lib2device[lib].append(device)
                else:
                    lib2device[lib] = [device]

bin2ctr = dict(sorted(bin2ctr.items(), key=lambda item: item[1]))
print(bin2ctr)

blocklist = []

for bin, ctr in bin2ctr.items():
    print(f'{ctr}: {bin}, {lib2device[bin]}')
    if ctr > CUTOFF:
        blocklist.append(bin)

blocklist.append("libc++_shared.so")

open("library_blocklist.txt", "w+").write("\n".join(blocklist))