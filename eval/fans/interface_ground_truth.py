import os
import sys
import argparse

BASE_DIR = os.path.dirname(__file__)
sys.path.append(os.path.join(BASE_DIR, "..", ".."))
sys.path.append(os.path.join(BASE_DIR, "..", "..", "fuzz"))

import data.database as database
import fuzzparcel
from config import TARGET_DIR

binder_db = database.open_db()

def print_interface_info_s(device, service):
    preproc_path = os.path.join(TARGET_DIR, device, service, "preprocess", "final")
    if not os.path.exists(preproc_path):
        print(f'no preprocess/final folder for {device} {service}')
        return
    cmd_ids = [str(c) for c in list(sorted([int(c) for c in os.listdir(preproc_path)]))]
    svc_entry = database.get_service(binder_db, service, device)
    service_binary = svc_entry.onTransact.bin
    onTransact_offset = svc_entry.onTransact.entry_addr
    print(f'=========================={device}:{service}==========================================')
    print(f'path: {os.path.join(TARGET_DIR, device, service, os.path.basename(service_binary))}')
    print(f'onTransact offset: {hex(onTransact_offset)}')
    for cmd in cmd_ids:
        for f in os.listdir(os.path.join(preproc_path, cmd)):
            fuzzparcel.py_print_info(os.path.join(preproc_path, cmd, f))
            print(10*"*")
    preproc_path = os.path.join(TARGET_DIR, device, service, "preprocess", "crashing")
    if not os.path.exists(preproc_path):
        print(f'no preprocess/final folder for {device} {service}')
        return
    cmd_ids = [str(c) for c in list(sorted([int(c) for c in os.listdir(preproc_path)]))]
    for cmd in cmd_ids:
        for f in os.listdir(os.path.join(preproc_path, cmd)):
            fuzzparcel.py_print_info(os.path.join(preproc_path, cmd, f))
            print(10*"*")
    print(20*'=')

def print_interface_info(device, service):
    if service is not None:
        print_interface_info_s(device, service)
        return
    for s in os.listdir(os.path.join(TARGET_DIR, device)):
        p = os.path.join(TARGET_DIR, device, s)
        if not os.path.isdir(p):
            continue
        dir_entries = os.listdir(p)
        if len([a for a in dir_entries if os.path.isdir(os.path.join(p, a))]) == len(dir_entries):
            # looking at / service name
            for s_2 in dir_entries:
                s = f'{s}/{s_2}'
                if not os.path.exists(os.path.join(TARGET_DIR, device, s, "preprocess")):
                    continue
                print_interface_info_s(device, s)
        else:
            if not os.path.exists(os.path.join(TARGET_DIR, device, s, "preprocess")):
                continue
            print_interface_info_s(device, s)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=f'convenience script for ground truth analysis of interface extraction')
    parser.add_argument("-d", "--device",  type=str, required=True, help="Device")
    parser.add_argument("-s", "--service",  type=str, required=False, help="Service")
    args = parser.parse_args()
    print_interface_info(args.device, args.service)
