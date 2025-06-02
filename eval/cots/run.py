import os
import subprocess
import json
import argparse
import frida
import logging
import re
import threading
import sys
from datetime import datetime
import time

BASE_DIR = os.path.dirname(__file__)
REPO_BASE = os.path.join(BASE_DIR, "..", "..")
sys.path.append(REPO_BASE)
sys.path.append(os.path.join(REPO_BASE, "fuzz"))

import service.vanilla as vanilla
import data.database as database
import data.get_non_default_services as non_default
import utils.utils as utils
import adb
import nass_api
from config import (
    PAIN, 
    SKIP_SERVICES,
    RED,
    NC,
    TARGET_DIR,
    PREPOCESS_DIR_NAME,
    PREPROCESS_FINAL_DIR
)

if len(logging.root.handlers) == 0:
    if not os.path.exists(os.path.join(BASE_DIR, "log")):
        os.system(f'mkdir -p {os.path.join(BASE_DIR, "log")}')
    logging.basicConfig(
        filename=os.path.join(BASE_DIR, "log", "run.log"),
        encoding="utf-8",
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(filename)s.%(funcName)s %(message)s",
        force=True,
    )

if "FUZZ_TIME" in os.environ:
    FUZZ_TIME = int(os.environ["FUZZ_TIME"])
else:
    FUZZ_TIME = 60 * 60 * 1  # 1 hour of fuzzing each service
MAX_RESTARTS = 10  # after X reboots move on to next service
MAX_CRASHES = 60

binder_db = database.open_db()


def filter_services(device_id, services):
    out =[]
    if device_id in PAIN:
        pain = PAIN[device_id]
    else:
        pain = [] 
    if device_id in SKIP_SERVICES:
        skip = SKIP_SERVICES[device_id] 
    else:
        print(f'{RED}FOOL CONFIGURE SKIP_SERVICES OR YOU PROBABLY BRICK THE DEVICE!!!!{NC}')
        exit(-1)
    for s in services:
        if s in skip:
            continue
        if s in pain:
            continue
        out.append(s) 
    return out
    

def log(msg):
    logging.info(msg)
    print(f'[RUN] {msg}')

def get_done_services(out_json):
    services_done = []
    for s, p in out_json.items():
        if p is None:
            continue
        if os.path.exists(p):
            services_done.append(s)
    return services_done

def run(device_id, out_prefix, fuzz_time, resume_file=None, service_txt=None):
    logging.info(f"starting fuzz runner for : {device_id}")
    print(f"starting fuzz runner for : {device_id}")
    if service_txt is not None:
        services = open(service_txt).read().split("\n")
        services = [s for s in services if len(s)>1]     
    else:
        services = database.single_select(
            binder_db,
                f'select service_name from service where onTransact_entry!=-1 and binary_path not LIKE "%app_process64%" and onTransact_bin not LIKE "%libandroid_runtime.so%" and device=="{device_id}";',
        )
        non_default_services = non_default.get_non_default_services(device_id)
        services = list(set(services).intersection(non_default_services))
    services = filter_services(device_id, services)
    out_dir = os.path.join(BASE_DIR, "run_out")
    if resume_file:
        out_path = resume_file
        out_json = json.load(open(out_path))
        services_done = get_done_services(out_json)
    else:
        out_name = f'{device_id}_{out_prefix}.json'
        out_path = os.path.join(out_dir, out_name)
        out_json = {}
        services_done = []
    if not os.path.isdir(out_dir):
        os.mkdir(out_dir)
    
    for s in services:
        if s in services_done:
            log(f'skipping {s}')
            continue
        log(f'working on {s}')
        preprocess_dir = os.path.join(TARGET_DIR, device_id, s, PREPOCESS_DIR_NAME, PREPROCESS_FINAL_DIR)
        if not os.path.exists(preprocess_dir):
            log(f'{preprocess_dir} does not exist, running preprocessing')
            try:
                nass_api.preprocess(
                    s,
                    device_id,
                )
            except adb.ADBDeviceNotFound:
                log(f'waiting for device')
                adb.wait_for_device(device_id)
        log(f'starting fuzzing')
        try:
            fuzz_out = nass_api.orchestrate_fuzz(
                s, 
                device_id,
                corpus_dirs= [preprocess_dir],
                fuzz_data=True,
                fuzz_time=fuzz_time,
                dump=True
            )
            out_json[s] = fuzz_out
        except adb.ADBDeviceNotFound:
            log(f'waiting for device')
            adb.wait_for_device(device_id)
        log(f'finished fuzzing dumping to output {out_path}')
        open(
            out_path,
            "w+",
        ).write(json.dumps(out_json)) 


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=f"fuzz all services of a device")
    parser.add_argument(
        "-d",
        "--device",
        type=str,
        required=True,
        help="which devce to fuzz",
    )
    parser.add_argument(
        "-n",
        "--name",
        type=str,
        required=True,
        help="prefix for the output json",
    )
    parser.add_argument(
        "-s",
        "--service_txt",
        type=str,
        required=False,
        help="file to a list of services to fuzz",
    )
    parser.add_argument(
        "-r",
        "--resume",
        type=str,
        required=False,
        help="resume from existing run_out/... json file",
    )
    parser.add_argument(
        "-t",
        "--time",
        type=int,
        required=False,
        help="time to fuzz each service",
    )
    args = parser.parse_args()

    if args.time is None:
        args.time = FUZZ_TIME

    run(args.device, args.name, args.time, resume_file=args.resume, service_txt=args.service_txt)
