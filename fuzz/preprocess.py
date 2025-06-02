import threading
import subprocess
import frida
import argparse
import os
import logging
import traceback
import sqlite3
import sys
from datetime import datetime
import time
import json
import tempfile

BASE_DIR: str = os.path.dirname(__file__)
sys.path.append(BASE_DIR)
sys.path.append(os.path.join(BASE_DIR, ".."))

from config import (
    LIBRARY_BLOCKLIST,
    TARGET_DIR,
    PREPOCESS_DIR_NAME,
    PREPOCESS_CMDID_DIR,
    PREPOCESS_ITERATION_DIR_PREFIX,
    PREPOCESS_FUZZ_BACK,
    PREPROCESS_FINAL_DIR,
    PREPROCESS_CRASHING_DIR,
    SHMEM,
    FRIDA_MAP_SIZE,
    TMPFS,
    FRIDA_SERVER_DIR,
    PHASE_2_SEED_DIRNAME,
    PAIN,
    FRIDA_VERSION,
    FANS_PIXEL_2_XL,
    RED, 
    NC,
    META_TARGET,
    IS_EMULATOR,
    AARCH64_EMU_28
)
import nass_api
import service.vanilla as vanilla
import data.database as database
import emulator.emulator as emulator
import adb
import fuzzparcel
from collections import defaultdict

MAX_ITERATIONS= 5

if len(logging.root.handlers) == 0:
    logging.basicConfig(
        filename=os.path.join(BASE_DIR, "log", "preprocessing.log"),
        encoding="utf-8",
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(filename)s.%(funcName)s %(message)s",
        force=True,
    )

def run_cmd(cmd):
    logging.debug(f'>>>[OSCMD]>>> {cmd}')
    subprocess.check_output(cmd, shell=True)

def wait_log(msg):
    print(msg)

class InterfaceExtractor():
    def __init__(self, 
                service_name: str, 
                device: frida.core.Device, 
                service: vanilla.Service,
                binder_db,
                meta_device_id=None,
                resume=None
                ) -> None:
        self.service_name = service_name
        self.device = device
        self.device_id = device.id
        if meta_device_id is None:
            self.meta_device_id = self.device_id 
        else:
            self.meta_device_id = meta_device_id
        self.service = service
        self.binder_db = binder_db
        self.target_path = os.path.join(
            TARGET_DIR, self.meta_device_id, self.service_name
        )
        self.out_path = os.path.join(self.target_path, PREPOCESS_DIR_NAME)
        self.resume = resume
        self.interface = {}
        self.new_interface = {}
        self.crashing_cmd_ids = []

    def log(self, msg):
        logging.info(f'[EXTRACTOR]{msg}')
        print(f'[EXTRACTOR] {msg}')

    def move_fuzz_out(self, intermediate_fuzz_dir):
        backup_dir = os.path.join(self.target_path, PREPOCESS_FUZZ_BACK)
        if not os.path.exists(backup_dir):
            run_cmd(f'mkdir -p {backup_dir}')
        run_cmd(f'cp -r {intermediate_fuzz_dir} {backup_dir}/')

    def collect_interface(self, refined_seed_dir):
        interface = {}
        for cmd_id in os.listdir(refined_seed_dir):
            for seed in os.listdir(os.path.join(refined_seed_dir, cmd_id)):
                f_p = os.path.join(refined_seed_dir, cmd_id, seed)
                deser_p = fuzzparcel.deserialize_parcel(open(f_p, 'rb').read())
                if deser_p is None:
                    logging.error(f'failed deserializing {f_p}, removing invalid seed')
                    run_cmd(f'rm {f_p}')
                    continue
                interface[cmd_id] = [t.argtype.name for t in deser_p.entries]
        return interface

    def interface_updated(self):
        if self.new_interface == {}:
            return True
        new_deserializer_found = False
        for cmd_id in self.new_interface:
            if cmd_id not in self.interface:
                new_deserializer_found = True
                continue
            if len(self.new_interface[cmd_id]) > len(self.interface[cmd_id]):
                if int(cmd_id) == 1598311760 and META_TARGET==AARCH64_EMU_28:
                    continue
                new_deserializer_found = True
                self.log(f'{cmd_id} discovered new deserializers {self.new_interface[cmd_id]}')
                continue 
            if len(self.new_interface[cmd_id]) < len(self.interface[cmd_id]):
                self.log(f'{cmd_id} REGRESSION... old: {self.interface[cmd_id]}, new: {self.new_interface[cmd_id]}')
                self.new_interface[cmd_id] = self.interface[cmd_id]
        self.interface = self.new_interface
        return new_deserializer_found

    def enumerate_cmd_ids(self):
        # run fuzzer in cmd id enumeration mode
        cmd_id_out = os.path.join(self.out_path, PREPOCESS_CMDID_DIR) 
        if not os.path.exists(cmd_id_out):
            run_cmd(f'mkdir -p {cmd_id_out}')
        self.log('starting the orchestrator fuzzing for cmd id enumeration')
        fuzz_out_dir = nass_api.orchestrate_fuzz(
            self.service_name, 
            self.device_id, 
            fuzz_code=True, 
            cov_rate=True
        )
        self.log('finished orchestrator fuzzing for cmd id enumeration')
        # move resulting seeds to cmdids folder
        gen_seed_dir = os.path.join(fuzz_out_dir, "data")
        run_cmd(f'cp {gen_seed_dir}/* {cmd_id_out}/')
        self.move_fuzz_out(fuzz_out_dir)
        # print results
        cmd_ids = set()
        for f in os.listdir(cmd_id_out):
            f_p = os.path.join(cmd_id_out, f)
            if f.startswith("seed-"):
                run_cmd(f'rm {f_p}')
                continue
            deser_p = fuzzparcel.deserialize_parcel(open(f_p, 'rb').read())
            if deser_p is None:
                logging.error(f'failed deserializing {f_p}, removing invalid seed')
                run_cmd(f'rm {f_p}')
                continue
            cmd_ids.add(
                deser_p.code
            )
        self.log(f'cmd ids discovered: {list(sorted(cmd_ids))}')
        if len(cmd_ids) == 0:
            self.log(f'no command ids discovered, exiting...')
            exit(-1)
        for cmd_id in cmd_ids:
            self.interface[cmd_id] = []
        for f in os.listdir(fuzz_out_dir):
            p = os.path.join(fuzz_out_dir, f)
            if f.startswith("crash-") and not os.path.isdir(p):
                deser_p = fuzzparcel.deserialize_parcel(open(p, 'rb').read())
                if deser_p is None:
                    continue
                if deser_p.code not in self.crashing_cmd_ids:
                    self.crashing_cmd_ids.append(deser_p.code)
                    self.log(f'crashing command id discovered: {deser_p.code}, \
                             storing for future use')

    def fuzz_and_refine(self, iteration):
        self.log(
            f'starting fuzzing + refinement step {iteration}'
        )
        iter_out = os.path.join(
            self.out_path, f'{PREPOCESS_ITERATION_DIR_PREFIX}{iteration}'
        )
        if not os.path.exists(iter_out):
            run_cmd(f'mkdir -p {iter_out}')
        cmd_id_seeds = os.path.join(
                    self.out_path, PREPOCESS_CMDID_DIR
            )
        previous_seed_corpus = None 
        if iteration == 0:
            previous_seed_corpus = cmd_id_seeds
        else:
            previous_seed_corpus = os.path.join(
                self.out_path, f'{PREPOCESS_ITERATION_DIR_PREFIX}{iteration-1}'
            )
        self.log(f'starting orchestrator for fuzzing parcel structure')
        adb.execute_privileged_command(f'rm -rf /data/local/tmp/fuzz/data/*', 
                                       device_id=self.device_id)
        adb.push_privileged(cmd_id_seeds, '/data/local/tmp/fuzz/data/', 
                            is_directory=True, device_id=self.device_id)
        fuzz_out_dir = nass_api.orchestrate_fuzz(
            self.service_name, 
            self.device_id, 
            corpus_dirs = [previous_seed_corpus],
            fuzz_parcel=True, 
            cov_rate=True
        )
        self.log(f'finished orchestrator fuzzing for parcel structure')
        if fuzz_out_dir is None or len(os.listdir(fuzz_out_dir)) == 0:
            self.log(f'orchestrator failed to run, pls check orchestrator log')
            return False
        gen_seed_dir = os.path.join(fuzz_out_dir, "data")
        if not os.path.exists(gen_seed_dir):
            self.log(f'orchestrator failed no data dir..')
            return False
        if IS_EMULATOR:
            emulator.reset(self.device_id)
        else:
            try:
                while adb.is_device_offline(self.device_id):
                    self.log('device offline hard resetting')
                    time.sleep(5)
            except adb.ADBDeviceNotFound:
                pass
        adb.wait_for_device(self.device_id, timeout=60*60, log_func=wait_log, 
                            log_msg=f'waiting for {self.device_id} to come back up...')
        self.log(
            f'starting refining step with {len(os.listdir(gen_seed_dir))} seeds'
        )
        refined_seeds_dir = nass_api.refine(
            self.service_name,
            self.device_id,
            fuzz_out_dir
        )
        self.log(f'finished refinement')
        if refined_seeds_dir is None or len(os.listdir(refined_seeds_dir)) == 0:
            self.log(f'no refined seeds in {refined_seeds_dir}, returning False')
            return False 
        self.new_interface = self.collect_interface(refined_seeds_dir)
        # move results to out path
        run_cmd(f'cp -r {refined_seeds_dir}/* {iter_out}/')
        self.move_fuzz_out(fuzz_out_dir)
        return True

    def check_crashing(self, seed_dir) -> list[tuple[str, str]]:
        out = []
        for cmd_id in os.listdir(seed_dir):
            cmd_id_path = os.path.join(seed_dir, cmd_id)
            for seed in os.listdir(cmd_id_path):
                seed_path = os.path.join(cmd_id_path, seed) 
                self.log(f'checking if final seed {seed_path} crashes')
                crashed = nass_api.check_crashing(
                    self.service_name,
                    self.device_id,
                    seed_path
                )
                if crashed:
                    out.append((cmd_id, seed_path))
        return out

    def dump_vtable(self):
        if not os.path.exists(os.path.join(self.target_path, "onTransact_vtable.txt")):
            self.log(f'onTransact dump does not exist yet, dumping vtable')
            run_cmd(f'python3 {BASE_DIR}/../instrument/dump_vtable.py -s {self.service_name} -d {self.device_id}')
            self.log(f'finished dumping vtable...')

    def extract(self):
        self.log(
            f'starting to setup extraction for {self.device_id}:{self.service_name}'
        )
        # backup previous prepocessing data if it exists
        if self.resume is None:
            if os.path.exists(self.out_path):
                backup_path = os.path.join(self.target_path, "preprocess_backup")
                if not os.path.exists(backup_path):
                    run_cmd(f'mkdir -p {backup_path}')
                backup_dir = os.path.join(
                            backup_path, 
                            f'{datetime.now().strftime("%d.%m.%Y_%H%M%S")}_backup'
                            )
                run_cmd(f'mkdir -p {backup_dir}')
                run_cmd(f'mv {self.out_path}/* {backup_dir}/')
            else:
                run_cmd(f'mkdir {self.out_path}')
        else:
            if not os.path.exists(self.resume):
                self.log(f'WARNING resume path not specified')
                exit(-1)
        if self.resume is None:
            # run cmd id extraction
            self.enumerate_cmd_ids()
            start_iteration = 0
        else:
            start_iteration = int(os.path.basename(self.resume.strip("/")).split("ie_")[-1])+1
            self.log(f'resume start iteration {self.resume} -> {start_iteration}')
        # iteratively refine seeds
        final_iteration = 0
        i = start_iteration
        while self.interface_updated():
            if not self.fuzz_and_refine(i):
                self.log(f'iteration {i} failed miserably')
                exit(-1)
            i+= 1
            final_iteration += 1
            if i > MAX_ITERATIONS:
                break
        # copy final seeds
        if i == 0:
            final_data_dir = os.path.join(
                self.out_path, 
                f'{PREPOCESS_CMDID_DIR}'
            )
        else:
            final_data_dir = os.path.join(
                self.out_path, 
                f'{PREPOCESS_ITERATION_DIR_PREFIX}{i-1}'
            )
        final_dir = os.path.join(self.out_path, PREPROCESS_FINAL_DIR)
        if not os.path.exists(final_dir):
            run_cmd(f'mkdir -p {final_dir}')
        run_cmd(f'cp -r {final_data_dir}/* {final_dir}/')
        # check if any of the final seeds directly crash the service
        # if they do we remove them from the preprocessing seed corpus
        # since otherwise it's very likely we'll just keep hitting these shallow
        # crashes during fuzzing
        crashing_seeds = self.check_crashing(final_dir)
        crashing_dir = os.path.join(self.out_path, PREPROCESS_CRASHING_DIR)
        run_cmd(f'mkdir -p {crashing_dir}')
        for cmd_id, s in crashing_seeds:
            crash_cmd_id = os.path.join(crashing_dir, cmd_id)
            if not os.path.exists(crash_cmd_id):
                run_cmd(f'mkdir -p {crash_cmd_id}')
            run_cmd(f'mv {s} {crash_cmd_id}')
            if len(os.listdir(os.path.join(final_dir, cmd_id))) == 0:
                self.log(f'all seeds for {cmd_id} crash, removing it')
                run_cmd(f'rm -rf {os.path.join(final_dir, cmd_id)}')
        open(os.path.join(self.out_path, 'interface.json'), 'w+').write(json.dumps(self.interface, sort_keys=True, indent=4))
        self.log(f'finished extractor phase, results at : {final_dir}') 

if __name__ == "__main__":

    ############################################################################
    # set up argument parser
    ############################################################################

    parser = argparse.ArgumentParser(
        description=f"Dynamically extract the interface of a service"
    )
    parser.add_argument(
        "-s",
        "--service_name",
        type=str,
        required=True,
        help="name of native service to fuzz",
    )
    parser.add_argument(
        "-d", "--device", type=str, required=True, help="device to test"
    )
    parser.add_argument(
        "-r",
        "--resume",
        type=str,
        required=False,
        help="continue preprocessing from given directory"
    )
    
    args = parser.parse_args()

    if args.device not in adb.get_device_ids():
        if IS_EMULATOR:
            print(f'[ORC] emulator starting up')
            emulator.full_reset(args.device)
        else:
            print(f'{RED} device {args.device} not connected')
            exit(-1)

    if not IS_EMULATOR:
        try:
            adb.reset_service(
                args.service_name,
                device_id=args.device,
                timeout=60,
            )
        except adb.ADBTimeoutException:
            print("timeout while waiting for service, rebooting device")
            adb.reboot(device_id=args.device)
            adb.wait_for_device(device_id=args.device, timeout=60*5)
            print("finished reset, starting")

    ############################################################################
    # select device to fuzz on
    ############################################################################

    devices = frida.enumerate_devices()
    possible_devices = [d for d in devices if d.type == "usb"]
    possible_devices = [
        d for d in possible_devices if not "ios" in d.name.lower()
    ]
    device = None
    if args.device not in [d.id for d in possible_devices]:
        print(f"{RED}[-] device not connected!{NC}")
        print(
            f"connected devices: ",
            ",".join([d.id for d in possible_devices]),
        )
    else:
        device = [d for d in possible_devices if d.id == args.device][0]

    if device is None:
        exit(-1)

    if device.id in PAIN:
        if args.service_name in PAIN[device.id]:
            print(f"{RED}NOT PREPROCESSING DEVICE DESTROYING SERVICE!!!{NC}")
            exit(-1)
    
    ############################################################################
    # retrieve target service info obtained from onTransact discovery
    ############################################################################

    binder_db = database.open_db()

    if META_TARGET is None:
        svc = database.get_service(binder_db, args.service_name, device.id)
    else:
        svc = database.get_service(binder_db, args.service_name, META_TARGET, 
                                            real_device_id=device.id)
    if svc is None or svc.onTransact is None:
        print(
            f"{RED}Service not in db, run interface onTransact enumeration first!{NC}"
        )
        exit(-1)
    
    ############################################################################
    # start interface extraction
    ############################################################################

    ie = InterfaceExtractor(
        args.service_name,
        device,
        svc,
        binder_db,
        meta_device_id=META_TARGET,
        resume = args.resume
    )

    ie.dump_vtable()

    ie.extract()
