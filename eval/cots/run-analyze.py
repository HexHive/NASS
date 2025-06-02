import sys
import os
import json
import argparse


BASE_DIR: str = os.path.dirname(__file__)
sys.path.append(os.path.join(BASE_DIR, "..", ".."))
sys.path.append(os.path.join(BASE_DIR, "..", "..", "fuzz"))

import triage 
import data.database as database
import data.get_non_default_services as non_default
import adb
from config import TARGET_DIR

binder_db = database.open_db()

def parse_logs(logs_path):
    return {"status": len(os.listdir(logs_path))}

def parse_outdir(output_path):
    seed_dir = os.path.join(output_path, "data")
    if os.path.exists(seed_dir):
        nr_seeds = len(os.listdir(seed_dir))-1
    else:
        nr_seeds = -1
    nr_crashes = len([c for c in os.listdir(output_path) if c.startswith("crash-")])
    nr_hangs = len([c for c in os.listdir(output_path) if c.startswith("timeout-")])
    log_path = os.path.join(output_path, "logs")
    if os.path.exists(log_path):
        log_info = parse_logs(log_path)
    else:
        log_info = {"status": "logs"}
    return {"path": output_path, "nr_seeds": nr_seeds, "nr_crashes": nr_crashes, "nr_hangs": nr_hangs, "log": log_info}

def parse_single(json_path):
    data = json.load(open(json_path))
    parsed = {}
    path_data = data["paths"]
    for i, device_path in enumerate(path_data):
        device = data[str(i)]
        parsed[device] = {}
        if device_path is None:
            continue
        for service, out_paths in device_path.items():
            if len(out_paths) == 0:
                continue
            assert len(out_paths) == 1, "??? out path incorrect ???"
            out_path = out_paths[0]
            
            fuzz_info = parse_outdir(out_path)
            parsed[device][service] = fuzz_info
    return parsed            

def print_info_out(s, o):
    if not os.path.exists(os.path.join(o, "logs")):
        print(f'logs dir does not exist')
        return 
    crashes_unique = triage.get_crashes(os.path.join(o, "logs"))
    nr_crashes = len([f for f in os.listdir(o) if f.startswith("crash-")])
    print(f'#### NR CRASHES: {nr_crashes} #### {o}')
    if len(crashes_unique) > 0:
        print(f"*****{o}*****")
    for c in crashes_unique:
        print(f'crash: {c.signal} {c.cause} {c.path}')

def print_info_deduplicated(d, s, out_path):
    nass_dedup = os.path.join(out_path, "nass_deduplicated")
    nass_dedup_old = os.path.join(out_path, "deduplicated")
    if not os.path.exists(nass_dedup) and not os.path.exists(nass_dedup_old):
        print(f'!!!!!!!!!!!!!!!!! NO CRASHES REPRODUCED !!!!!!!!!!!!!!!!!!!!!')
    if os.path.exists(nass_dedup) or os.path.exists(nass_dedup_old):
        print(f'@@@@@@@@@@REPRODUCED AND DEDUPLICATED@@@@@@@@@@@@@@@@@@@@')
    if os.path.exists(nass_dedup):
        print(nass_dedup)
        os.system(f'cat {os.path.join(nass_dedup, "info.txt")}')
    if os.path.exists(nass_dedup_old):
        print(nass_dedup_old)
        os.system(f'cat {os.path.join(nass_dedup_old, "info.txt")}')

def print_info_json(json_out, triaged_only, print_all_crashes):
    if not os.path.exists(json_out):
        print(f'{json_out} does not exist')
        return
    out_json = json.load(open(json_out))
    for s, o in out_json.items():
        print(f'=================={s}=========================')
        if o is None:
            print(f'entry path is None')
            continue
        if not print_all_crashes:
            nass_dedup = os.path.join(o, "..", "nass_deduplicated")
            if not os.path.exists(nass_dedup):
                nass_dedup = os.path.join(o, "..", "deduplicated")
                if not os.path.exists(nass_dedup):
                    print(f'!!!!!!!!!!!!!!!!! NO CRASHES REPRODUCED !!!!!!!!!!!!!!!!!!!!!')
                    nass_dedup = None
        if not print_all_crashes:
            if nass_dedup is not None:
                print(f'@@@@@@@@@@REPRODUCED AND DEDUPLICATED@@@@@@@@@@@@@@@@@@@@')
                print(o)
                os.system(f'cat {os.path.join(nass_dedup, "info.txt")}')
        if print_all_crashes:
            print_info_out(s, o)
        """
        if isinstance(o, str):
            print_info_out(s, o)
        elif isinstance(o, dict):
            for fuzzer, out_paths in o.items():
                print(f'================{fuzzer}=================')
                for o in out_paths:
                    print(o)
                    print_info_out(s, o) 
        """

def get_nr_crashes(d, s, out_path):
    all_crashes = 0
    all_repro = 0
    for out_dir in os.listdir(out_path):
        fuzz_out_dir = os.path.join(out_path, out_dir)
        fuzz_out_dir_entries = os.listdir(fuzz_out_dir)
        if "reproduced" not in fuzz_out_dir_entries:
            continue
        all_crashes += len([c for c in fuzz_out_dir_entries if c.startswith("crash-")])
        repro_crashes = os.listdir(os.path.join(fuzz_out_dir, "reproduced"))
        all_repro += len([c for c in repro_crashes if c.startswith("root-crash-") and not c.endswith("_crashdump.txt")])
    return all_crashes, all_repro
    

def print_info_device_service(d, s, triaged_only):
    print(f'=================={d}:{s}=========================')
    out_path = f'{TARGET_DIR}/{d}/{s}/fuzz_out'
    if not os.path.exists(out_path):
        #print(f'no fuzz_out {out_path} folder for {d}:{s}')
        return
    if triaged_only:
        print_info_deduplicated(d, s, out_path)
    #for o in os.listdir(out_path):
    #    o = os.path.join(out_path, o)
    #    print_info_out(s, o)
    
def print_info_device(d, triaged_only):
    print(f'=================={d}=========================')
    all_services = database.single_select(
            binder_db,
                f'select service_name from service where onTransact_entry!=-1 and binary_path not LIKE "%app_process64%" and onTransact_bin not LIKE "%libandroid_runtime.so%" and device=="{d}";',
        )
    non_default_services = non_default.get_non_default_services(d)
    fuzzed_services = list(set(all_services).intersection(non_default_services))
    target_services = os.path.join(TARGET_DIR, d)
    check_fuzzed = True
    if len(fuzzed_services) == 0:
        check_fuzzed = False
    all_crashes = 0
    all_crashes_reproduced = 0
    for s in os.listdir(target_services):
        p = os.path.join(target_services, s)
        if not os.path.isdir(p):
            continue
        dir_entries = os.listdir(p)
        if len([a for a in dir_entries if os.path.isdir(os.path.join(p, a))]) == len(dir_entries):
            # looking at / service name
            for s_2 in dir_entries:
                s = f'{s}/{s_2}'
                if not os.path.exists(os.path.join(TARGET_DIR, d, s, "fuzz_out")):
                    continue
                if s not in fuzzed_services and check_fuzzed:
                    continue
                print_info_device_service(d, s, triaged_only)
                ac, ap = get_nr_crashes(d, s, os.path.join(TARGET_DIR, d, s, "fuzz_out"))
                all_crashes += ac
                all_crashes_reproduced += ap
        else:
            if not os.path.exists(os.path.join(TARGET_DIR, d, s, "fuzz_out")):
                continue
            if s not in fuzzed_services and check_fuzzed:
                continue
            print_info_device_service(d, s, triaged_only)
            ac, ap = get_nr_crashes(d, s, os.path.join(TARGET_DIR, d, s, "fuzz_out"))
            all_crashes += ac
            all_crashes_reproduced += ap
    print("all crashes: ", all_crashes)
    print("all crashes reproduced: ", all_crashes_reproduced)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=f'analyze output json')
    parser.add_argument(
        "-j", 
        "--json_out",
        type=str, 
        required=False,
        help="path to the output json to be parsed")
    parser.add_argument(
        "-s",
        "--service",
        type=str,
        required=False,
        help="name of native service to fuzz",
    )
    parser.add_argument(
        "-d", "--device", type=str, required=False, help="device to test"
    )
    parser.add_argument(
        "-t", "--triaged", default=False, action="store_true", help="only show deduplicated crashes"
    )
    parser.add_argument(
        "-pa", "--print_all_crashes", default=False, action="store_true", help="print number of all crashes for a device"
    )

    args = parser.parse_args()

    if args.json_out is not None:
        print_info_json(args.json_out, args.triaged, args.print_all_crashes)
        exit(0)
    
    if args.device is not None:
        if args.service is not None:
            print_info_device_service(args.device, args.service, args.triaged)
            exit(0)
        else:
            print_info_device(args.device, args.triaged)
            exit(0)    

    print(f'specify -d, -s or -j')

