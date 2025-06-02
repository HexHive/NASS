import sys
import os
import json
import argparse


BASE_DIR: str = os.path.dirname(__file__)
REPO_BASE = os.path.join(BASE_DIR, "..", "..")
sys.path.append(REPO_BASE)
sys.path.append(os.path.join(REPO_BASE, "fuzz"))

import triage

import adb
from config import TARGET_DIR

def do_triage(service, out_path):
    os.system(f'python3 {REPO_BASE}/fuzz/triage.py -i {out_path}')


def run_triage(json_out):
    if not os.path.exists(json_out):
        print(f'{json_out} does not exist')
        return
    out_json = json.load(open(json_out))
    for s, o in out_json.items():
        print(f'=================={s}=========================')
        if o is None:
            print(f'entry path is None')
            continue
        if isinstance(o, str):
            do_triage(s, o)
        elif isinstance(o, dict):
            for fuzzer, out_paths in o.items():
                print(f'================{fuzzer}=================')
                for o in out_paths:
                    print(f'triaging: {s}:{o}')
                    do_triage(s, o) 


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=f'run triage over output json')
    parser.add_argument(
        "-j", 
        "--json_out",
        type=str, 
        required=False,
        help="path to the output json to be parsed")

    args = parser.parse_args()

    if args.json_out is not None:
        run_triage(args.json_out)
        exit(0)
    

