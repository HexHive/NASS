import random
import copy
import re
from collections import defaultdict
import os
import subprocess
import tempfile
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
sys.path.append(os.path.join(BASE_DIR, ".."))

from config import TARGET_DIR, SHMEM, FRIDA_MAP_SIZE, TMPFS, TRIAGE_FANS_DEDUP, META_TARGET, IS_EMULATOR
import service.vanilla as vanilla
import data.database as database
import emulator.emulator as emulator
import data.get_non_default_services as non_default
import utils.utils as utils
import adb


DEVICE = os.path.join(BASE_DIR, "..", "device")
TRIAGE_PATH = "/data/local/tmp/fans-cov"
TRIAGE_CRASHES = os.path.join(TRIAGE_PATH, "crashes")
TRIAGE_SEEDS = os.path.join(TRIAGE_PATH, "data")

logging.basicConfig(
    filename=os.path.join(BASE_DIR, "log", "fans-triage.log"),
    encoding="utf-8",
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(filename)s.%(funcName)s %(message)s",
    force=True,
)

binder_db = database.open_db()

"""
script to replay crashes, record the logcat tombstone dump
reproduced crashes are written to reproduced folder
"""

class Seed:
    def __init__(self, path):
        self.path = path
        self.name = os.path.basename(path)
        self.remote_path = os.path.join(TRIAGE_SEEDS, self.name)

class tombstoneLog:
    def __init__(self, backtrace, signal, cause) -> None:
        self.backtrace = backtrace
        self.signal = signal
        self.cause = cause 

    def __hash__(self):
        bt_str = ""
        for addr, bin in self.backtrace:
            bt_str += addr + ":" + bin
        return hash(bt_str+self.signal+self.cause)

    def __str__(self):
        bt_str = ""
        for addr, bin in self.backtrace:
            bt_str += addr + ":" + bin
        return f'tombstone:({self.signal},{self.cause}[{bt_str}])' 

    def __repr__(self):
        bt_str = ""
        for addr, bin in self.backtrace:
            bt_str += addr + ":" + bin
        return f'tombstone:({self.signal},{self.cause}[{bt_str}])'

    def __eq__(self, other):
        print(self.__hash__(), other.__hash__())
        return self.__hash__() == other.__hash__()


def parse_log(log:str) -> tombstoneLog:
    m = re.findall(r'#(\d+) pc ([0-9a-f]+)  ([^\s]+)', log)
    #TODO: multiple thread backtraces
    backtrace = [None] * len(m)
    for i, g in enumerate(m):
        idx = int(g[0])
        addr = g[1]
        bin = g[2]
        backtrace[i] = (addr, bin)
    print(backtrace)
    m = re.findall(r'signal ([^,]+)', log)
    if len(m) > 0:
        signal = m[0]
    else:
        signal = "unknown"
    m = re.findall(r'Cause: ([^\n]+)', log)
    if len(m) > 0:
        cause = m[0]
    else:
        m = re.findall(r'Abort message: ([^\n]+)', log)
        if len(m) > 0:
            cause = m[0]
        else:
            cause = "unknown"
    do_log(f'parsing crash log: {signal} {cause}, backtrace lenght:{len(backtrace)}')
    return tombstoneLog(backtrace, signal, cause)

def run_cmd(cmd):
    logging.debug(f'running: {cmd}')
    subprocess.check_output(cmd, shell=True)

def do_log(line):
    print(f'[TRIAGE] {line}')
    logging.info(line)

def setup_triage(device, service, triage_path, binder_db, meta_target):
    crashes = 0
    for f in os.listdir(triage_path):
        if f.startswith("crash-"):
            crashes += 1
    if crashes == 0:
        do_log(f'no crashes in {triage_path}, skipping')
        return -1
    do_log(f'setting up the device..')
    setup_device(device, service, binder_db, meta_target)
    do_log(f'uploading seeds and crashes..')
    for f in os.listdir(triage_path):
        if f.startswith("crash-"):
            crashes += 1
            adb.push_privileged(os.path.join(triage_path,f), TRIAGE_CRASHES, device_id=device)
    if not os.path.exists(os.path.join(triage_path, "data")):
        do_log(f'{os.path.join(triage_path, "data")} does not exist, corrupted out directory?')
    else:
        #for s in os.listdir(os.path.join(triage_path, "data")):
        adb.push_privileged(os.path.join(triage_path, "data"), TRIAGE_PATH, device_id=device, is_directory=True)
     
    adb.execute_privileged_command(f'chmod -R 777 {TRIAGE_PATH}', device_id=device)
    do_log(f'done setting up')

def setup_device(device, service, binder_db, meta_target):
    if not adb.path_exists(TRIAGE_PATH, device_id=device):
        adb.execute_privileged_command(f'mkdir {TRIAGE_PATH}', device_id=device)
        adb.execute_privileged_command(f'chmod 777 {TRIAGE_PATH}', device_id=device)
    fuzzer_path = os.path.join(BASE_DIR, "native_service_fuzzer_coverage")
    if not os.path.exists(fuzzer_path):
        print(f"[ERROR] please compile fuzzer for {device}")
        exit(-1)
    adb.push_privileged(fuzzer_path, f'{TRIAGE_PATH}', device_id=device)
    adb.push_privileged(
            os.path.join(BASE_DIR, 'seed'), TRIAGE_PATH, is_directory=True, 
            device_id=device
            )
    adb.push_privileged(
            os.path.join(BASE_DIR, 'workdir/interface-model-extractor/model'), 
            TRIAGE_PATH, is_directory=True, device_id=device
            )
    adb.push_privileged(
            os.path.join(BASE_DIR, 'fuzzer-engine/fuzzer-coverage'), TRIAGE_PATH, 
                         is_directory=True, device_id=device
            )
    # upload triage data
    adb.execute_privileged_command(f'rm -rf {TRIAGE_CRASHES}', device_id=device)
    adb.execute_privileged_command(f'rm -rf {TRIAGE_SEEDS}', device_id=device)
    adb.execute_privileged_command(f'mkdir -p {TRIAGE_CRASHES}', device_id=device)
    adb.execute_privileged_command(f'mkdir -p {TRIAGE_SEEDS}', device_id=device)

def sort_seeds(seeds: list[Seed]) -> list[Seed]:
    raw_list = []
    for f in seeds:
        if f.name.endswith(".rng"):
            continue
        if f.name.startswith("seed-"):
            continue
        if os.path.isdir(f.path):
            continue
        iteration, sha1, timestamp = f.name.split("-")
        timestamp = int(timestamp)
        iteration = int(iteration)
        raw_list.append((iteration, timestamp, f))
    ordered_data_seeds = [d[2] for d in sorted(raw_list, key=lambda x: (x[1], x[0]))]
    return ordered_data_seeds
   
def get_seeds_up_to(seeds: list[Seed], crash) -> list[Seed]:
    raw_list = []
    try:
        crash_timestamp = int(crash.split("-")[-1])
    except:
        return seeds
    for f in seeds:
        iteration, sha1, timestamp = f.name.split("-")
        timestamp = int(timestamp)
        iteration = int(iteration)
        if timestamp <= crash_timestamp:
            raw_list.append((iteration, timestamp, f))
    ordered_data_seeds = [d[2] for d in sorted(raw_list, key=lambda x: (x[1], x[0]))]
    return ordered_data_seeds

def get_seeds(triage_path):
    seed_path = os.path.join(triage_path, "data")
    if not os.path.exists(seed_path):
        return []
    seeds = [Seed(os.path.join(seed_path, f)) for f in os.listdir(seed_path)]
    #seeds = os.listdir(seed_path)
    # handle new seed format: nr-hash
    return sort_seeds(seeds)

def split_seeds(seeds: list[Seed]) -> list[list[Seed]]:
    def split_array(arr, size):
        return [arr[i:i + size] for i in range(0, len(arr), size)]
    chunk_size = 1000
    seeds_split = split_array(seeds, chunk_size)
    return seeds_split

def rerun_crash(device, service, crash, triage_path):
    output = []
    env = f"NOSHM=1"
    cmd = f"cd {TRIAGE_PATH} && {env} ./native_service_fuzzer_coverage --replay_seed {TRIAGE_CRASHES}/{crash}"
    adb.kill_service(service.service_name, device)
    adb.wait_ready(service.service_name, device)
    logging.info(cmd)
    do_log(f'replaying {crash}!')
    adb.clear_logcat(device)
    initial_pid = adb.get_service_pid(service.service_name, device_id=device)
    # TODO if not reproduced by single replay try doing it by replaying multiple seeds
    out, err = adb.execute_privileged_command(cmd, device_id=device)
    time.sleep(1) # wait a bit, sometimes the crash is desynced from the seed
    second_pid = adb.get_service_pid(service.service_name, device_id=device)
    crash_log = adb.logcat_crashlog(device)
    adb.execute_privileged_command(f'rm {TRIAGE_PATH}/.pid', device_id=device)
    crashed_root = False
    crash_log_root = None
    crashed_nobody = False
    reproduced = False
    if initial_pid != second_pid:
        do_log(f'crash reproduced! pid initial: {initial_pid}, second pid: {second_pid}')
        crashed_root = True
        crash_log_root = crash_log
        reproduced = True 
        output.append(
            {
                "cmd": cmd, 
                "user": "root", 
                "crash": crash, 
                "log": crash_log_root, 
                "nostate": True,
                "seed_path": os.path.join(triage_path, "data")
            }
        )
    """
    if crashed_root:
        adb.wait_ready(service.service_name, device)
        initial_pid = adb.get_service_pid(service.service_name, device_id=device, no_dumpsys_device=FANS_PIXEL_2_XL)
        do_log('replaying crash as nobody user!')
        adb.clear_logcat(device)
        time.sleep(1)
        out, err = adb.execute_nobody_command(cmd, device_id=device)
        time.sleep(1) # wait a bit, sometimes the crash is desynced from the seed
        second_pid = adb.(service.service_name, device_id=device)
        crash_log = adb.logcat_crashlog(device)
        adb.execute_privileged_command(f'rm {TRIAGE_PATH}/.pid', device_id=device)
        if b"libFuzzer: deadly signal" in err or initial_pid != second_pid:
            do_log(f'crash reproduced as nobody!! {initial_pid},{second_pid}')
            crashed_nobody = True
            crash_nobody = crash_log
            output.append({"user": "nobody", "crash": crash, "log": crash_nobody, "nostate": True})
    """
    if reproduced:
        do_log(f'crash reproduced returning')
        return output
    do_log(
        f'crash not reproduced with single crashing seed, replaying seed corpus'
    )
    cmds = []
    seeds = get_seeds(triage_path) 
    seeds = get_seeds_up_to(seeds, crash)
    seeds_split = split_seeds(seeds) 
    for seeds in seeds_split:
        for s in seeds:
            cmds.append(f"cd {TRIAGE_PATH} && {env} ./native_service_fuzzer_coverage --replay_seed {s.remote_path}")
    cmds.append(f"cd {TRIAGE_PATH} && {env} ./native_service_fuzzer_coverage --replay_seed {TRIAGE_CRASHES}/{crash}")
    adb.kill_service(service.service_name, device)
    adb.wait_ready(service.service_name, device)
    do_log(f'replaying seeds: {len(seeds)}')
    initial_pid = adb.get_service_pid(service.service_name, device_id=device)
    adb.clear_logcat(device)
    for i in range(0, 3):
        # run a few times just to test
        for cmd in cmds:
            do_log(f'replaying seeds {cmd}')
            out, err = adb.execute_privileged_command(cmd, device_id=device) 
        #seed_command = f"{TRIAGE_CRASHES}/{crash}"
        #cmd = f"cd {TRIAGE_PATH} && {env} ./fuzzer {seed_command}" 
        #do_log(f'replaying crash: {crash} {cmd}')
        #out, err = adb.execute_privileged_command(cmd, device_id=device)
        adb.execute_privileged_command(f'rm {TRIAGE_PATH}/.pid', device_id=device)
        time.sleep(1) # wait a bit, sometimes the crash is desynced from the seed
        crash_log = adb.logcat_crashlog(device)
        second_pid = adb.get_service_pid(service.service_name, device_id=device)
        if b"libFuzzer: deadly signal" in err or initial_pid != second_pid:
            do_log(f'crash reproduced after replaying seeds! {initial_pid}, {second_pid}') 
            output.append(
                {
                    "cmd": "\n".join(cmds), 
                    "user": "root", 
                    "crash": crash, 
                    "log": crash_log, 
                    "nostate": False, 
                    "seeds": seeds,
                    "seed_path": os.path.join(triage_path, "data")
                },
            )
            # TODO replay as user
            return output
    do_log(f'unable to reproduce even with replaying seeds :(')
    return output

def dump_result(triage_path, result, service):
    run_cmd(f'mkdir -p {triage_path}/reproduced')
    do_log(f'dumping crash info to {triage_path}/reproduced/{result["user"]}-{result["crash"]}*')
    run_cmd(f'cp {triage_path}/{result["crash"]} {triage_path}/reproduced/{result["user"]}-{result["crash"]}')
    open(f'{triage_path}/reproduced/{result["user"]}-{result["crash"]}_crashdump.txt', 'w+').write(result["log"])
    env = f"DESER_PATH={TRIAGE_PATH}/deserializers_used.txt SERVICE_NAME={service.service_name} INTERFACE_NAME={service.onTransact.interface}"
    cmd = f"{env} ./fuzzer {TRIAGE_CRASHES}/{result['crash']}"
    open(f'{triage_path}/reproduced/replay.sh', 'w+').write(result['cmd'])
    if not result['nostate']:
        # copy seed path over
        run_cmd(f'cp -r {result["seed_path"]} {triage_path}/reproduced/')


def crash_reproduced(triage_path, crash):
    if os.path.exists(f'{triage_path}/reproduced'):
        for f in os.listdir(f'{triage_path}/reproduced'):
            if crash in f:
                return True
        return False
    else:
        return False

def rerun_crashes(device, service, triage_path, binder_db, meta_target, dont_rerun_reproduced=False, rerun_non_reproduced=True):
    adb.kill_service(service.service_name, device_id=device)
    crashes = [(f, os.path.join(triage_path, f)) for f in os.listdir(triage_path) if f.startswith("crash-")]
    crashes = [f for f in crashes if not f[0].endswith(".rng")]
    reproduced = []
    for crash, crash_path in crashes:
        if dont_rerun_reproduced and crash_reproduced(triage_path, crash):
            do_log(f'crash {crash} already reproduced')
            continue
        if not rerun_non_reproduced and not crash_reproduced(triage_path, crash):
            do_log(f'skipping {crash} not retrying non-reproduced crashes') 
            continue
        try:
            result = rerun_crash(device, service, crash, triage_path)
            if len(result) > 0:
                for r in result:
                    r["crash_path"] = crash_path
                    reproduced.append(r)
                    dump_result(triage_path, r, service)
        except (adb.ADBDeviceOffline, adb.ADBDeviceNotFound):
            do_log(f'adb device not found during rerun crashes...')
            r = {
                    "cmd": "..?",
                    "user": "root",
                    "crash": crash,
                    "log": "NO LOG DEVICE SHUTDOWN",
                    "nostate": True,
                    "seed_path": os.path.join(triage_path, "data"),
                    "crash_path": crash_path
                }
            reproduced.append(r)
            dump_result(triage_path, r, service)
        time.sleep(1)
        if IS_EMULATOR:
            emulator.reset(device)
            setup_triage(device, service, triage_path, binder_db, meta_target)
    return reproduced

def deduplicate_crashes(crashes):
    # [{"user": "nobody", "crash": crash, "log": crash_log_root}]
    out = defaultdict(list)
    for i,c in enumerate(crashes):
        out[parse_log(c["log"])].append(c)
    logging.debug(f'deduplication dictionary: {out}')
    for k,v in out.items():
        do_log(f'log: {k} : backtraces:{len(v)}')
    return_v = [v[0] for k,v in out.items()]
    logging.debug(f'deduplicated entries: {return_v}')
    return return_v

def get_crashlog(repro_folder):
    for f in os.listdir(repro_folder):
        if f.endswith("crashlog.txt"):
            return os.path.join(repro_folder, f)
    return None

def dump_deduplicated(dedup_folder, dedup_crash, service):
    new_dir_name = len(os.listdir(dedup_folder))
    if new_dir_name == 0:
        logging.debug(f'dedup folder is empty')
        run_cmd(f'touch {dedup_folder}/info.txt')
    else:
        new_dir_name -= 1
    new_dir = os.path.join(dedup_folder, str(new_dir_name))
    logging.debug(f'adding new folder: {new_dir}')
    run_cmd(f'mkdir {new_dir}')
    run_cmd(f'cp {dedup_crash["crash_path"]} {new_dir}')
    open(os.path.join(new_dir, "crashlog.txt"), "w+").write(dedup_crash["log"])
    parsed = parse_log(dedup_crash["log"])
    open(os.path.join(dedup_folder, "info.txt"), "a").write(f'{new_dir_name}: {parsed.signal},{parsed.cause}\n')
    env = f"DESER_PATH={TRIAGE_PATH}/deserializers_used.txt SERVICE_NAME={service.service_name} INTERFACE_NAME={service.onTransact.interface}"
    cmd = f"{env} ./fuzzer {TRIAGE_CRASHES}/{dedup_crash['crash']}"
    open(f'{new_dir}/replay.sh', 'w+').write(dedup_crash['cmd'])
    if not dedup_crash["nostate"]:
        # copy seeds over
        adb.pull_privileged(
            TRIAGE_SEEDS, f'{new_dir}', 
            device_id=service.device, is_directory=True
        )
        run_cmd(f'cp -r {dedup_crash["seed_path"]} {new_dir}')


def add_to_deduplicated(fuzz_out, deduplicated, service):
    # [{"user": "nobody", "crash": crash, "log": crash_log_root}
    # go through dedupllicated folders and check if the crash already exists
    # if not, create a new folder and dump all info in there
    all_existing = []
    deduplicated_folder = os.path.join(fuzz_out, TRIAGE_FANS_DEDUP)
    if not os.path.exists(deduplicated_folder):
        run_cmd(f'mkdir -p {deduplicated_folder}')
    for repro_folder in os.listdir(deduplicated_folder):
        if repro_folder == "info.txt":
            continue
        repro_folder = os.path.join(deduplicated_folder, repro_folder)
        if not os.path.isdir(repro_folder):
            continue
        crashlog = get_crashlog(repro_folder)
        if crashlog is None:
            logging.warning(f'weird no crashdump.txt')
            continue
        all_existing.append(parse_log(open(crashlog).read()))
    for dedup in deduplicated:
        dedup_tomb = parse_log(dedup["log"])
        if dedup_tomb in all_existing:
            logging.debug(f'crash : {dedup["crash"]} is already in reproduced crashes')
            continue
        dump_deduplicated(deduplicated_folder, dedup, service)
        all_existing.append(dedup_tomb)
        

def do_triage(device, service, out, meta_target=None, dont_rerun_reproduced=False, rerun_non_reproduced=True):
    if meta_target is None:
        meta_target = device
    fuzz_out_path = os.path.join(TARGET_DIR, meta_target, service, "fuzz_out")
    triage_path = os.path.join(fuzz_out_path, out)
    service_obj = database.get_service(binder_db, service, meta_target)
    do_log(f'triaging: {triage_path}')
    status = setup_triage(device, service_obj, triage_path, binder_db, meta_target=meta_target)
    if status == -1:
        return []
    crashes_reproduced = rerun_crashes(device, service_obj, triage_path, binder_db, meta_target, dont_rerun_reproduced=dont_rerun_reproduced, rerun_non_reproduced=rerun_non_reproduced)
    deduplicated = deduplicate_crashes(crashes_reproduced)
    if len(deduplicated) > 0:
        add_to_deduplicated(fuzz_out_path, deduplicated, service_obj)

def run_cmd_seeds(device, service, crash, seeds_split: list[list[Seed]], iters=3):
    env = f"NOSHM=1 DESER_PATH={TRIAGE_PATH}/deserializers_used.txt SERVICE_NAME={service.service_name} INTERFACE_NAME={service.onTransact.interface}"
    cmds = []
    for seeds in seeds_split:
        cmds.append(f"cd {TRIAGE_PATH} && {env} ./fuzzer {' '.join([s.remote_path for s in seeds])}")
    cmds[-1] = cmds[-1] + f" {TRIAGE_CRASHES}/{crash}"
    adb.kill_service(service.service_name, device)
    adb.wait_ready(service.service_name, device)
    do_log(f'replaying seeds: {len(seeds)}')
    initial_pid = adb.get_service_pid(service.service_name, device_id=device)
    adb.clear_logcat(device)
    for i in range(0, iters):
        # run a few times just to test
        for cmd in cmds:
            do_log(f'replaying seeds {cmd}')
            out, err = adb.execute_privileged_command(cmd, device_id=device) 
        #seed_command = f"{TRIAGE_CRASHES}/{crash}"
        #cmd = f"cd {TRIAGE_PATH} && {env} ./fuzzer {seed_command}" 
        #do_log(f'replaying crash: {crash} {cmd}')
        #out, err = adb.execute_privileged_command(cmd, device_id=device)
        adb.execute_privileged_command(f'rm {TRIAGE_PATH}/.pid', device_id=device)
        time.sleep(1) # wait a bit, sometimes the crash is desynced from the seed
        crash_log = adb.logcat_crashlog(device)
        second_pid = adb.get_service_pid(service.service_name, device_id=device)
        if b"libFuzzer: deadly signal" in err or initial_pid != second_pid: 
            do_log(f'crashed!')
            return True
    do_log(f'no crash..')
    return False

def slice_seeds(seeds, minimizing_existing=False):
    def all_subarrays_of_size(arr, k):
        n = len(arr)
        if k > n or k <= 0:
            return []

        subarrays = []
        for i in range(n - k + 1):
            subarray = arr[i:i + k]
            subarrays.append(subarray)

        return subarrays
    def all_possible_subarrays(arr):
        subarrays = []
        n = len(arr)
        for start in range(n):
            for end in range(start + 1, n + 1 ):
                subarray = arr[start:end]
                if len(subarray) == len(arr):
                    continue
                subarrays.append(subarray)
        return subarrays
    size = len(seeds)
    size_1_2 = size // 2
    size_1_4 = size // 4
    slices = []
    slices.append(seeds[:size_1_2])
    slices.append(seeds[size_1_2:])
    if minimizing_existing:
        def all_combinations_ordered(arr, x):
            import itertools
            n = len(arr)
            if x > n or x <= 0:
                return []
            combinations = list(itertools.combinations(arr, x))
            return combinations
        if size <= 10:
            out = all_combinations_ordered(seeds, size-1) 
        else:
            out = []
            while len(out) < min(20, size - size_1_2):
                test = random.sample(seeds, size_1_2)
                test = sort_seeds(test)
                if test not in out and test not in slices:
                    out.append(test)
        random.shuffle(out)
        return out
        return out
        if size <= 10:
            out = all_subarrays_of_size(seeds, size-1)
        else:
            out =all_possible_subarrays(seeds) 
            random.shuffle(out)
        return out
    if size < 25 and size > 4:
        # more combinations
        samples = []
        while len(samples) < min(10, size - size_1_2):
            test = random.sample(seeds, size_1_2)
            test = sort_seeds(test)
            if test not in samples and test not in slices:
                samples.append(test)
        slices = slices + samples
    elif size <= 6:
        return all_possible_subarrays(seeds)
    return slices

def min_merge_slices(slices):
    #TODO: maybe something smarter
    shortest = min(slices, key=lambda x: len(x[0]))
    return shortest

def do_minimize(device, service, crash_id, meta_target=None, min_existing=True):
    if meta_target is None:
        meta_target = device
    service_obj = database.get_service(binder_db, service, meta_target)
    do_log('setting up on device')
    triage_path = os.path.join(TARGET_DIR, meta_target, service, "fuzz_out") 
    dedup_folder = os.path.join(triage_path, TRIAGE_FANS_DEDUP)
    crash_folder = os.path.join(dedup_folder, crash_id)
    crash_file = None
    for f in os.listdir(crash_folder):
        if f.startswith('crash-'):
            crash_file = f
            break
    print(crash_folder, crash_id)
    assert crash_file is not None, "failed to retrieve crash seed from dedup folder!"
    setup_device(device, service_obj, binder_db, meta_target=meta_target)
    if os.path.exists(dedup_folder):
        adb.push_privileged(dedup_folder, TRIAGE_CRASHES, device_id=device, is_directory=True)
        adb.execute_privileged_command(f'cp -r {TRIAGE_CRASHES}/deduplicated/*/data {TRIAGE_PATH}', device_id=device)
        adb.execute_privileged_command(f'cp {TRIAGE_CRASHES}/deduplicated/*/crash-* {TRIAGE_CRASHES}/', device_id=device)
        adb.execute_privileged_command(f'cd {TRIAGE_PATH} && for dir in ./crashes/deduplicated/*/; do folder=$(basename "$dir"); cp "$dir/replay.sh" "./replay_$folder.sh" && chmod +x "./replay_$folder.sh"; done', device_id=device) 
        adb.execute_privileged_command(f'cd {TRIAGE_PATH} && for dir in ./crashes/deduplicated/*/; do folder=$(basename "$dir"); cp "$dir/replay_min.sh" "./replay_min_$folder.sh" && chmod +x "./replay_min_$folder.sh"; done', device_id=device) 
    seed_min_path = os.path.join(crash_folder, 'seeds_min.txt')
    minimizing_existing = False
    if os.path.exists(seed_min_path) and min_existing:
        do_log(f'minimizing existing min seeds!')
        minimizing_existing = True
        seeds = open(seed_min_path).read().split('\n')
    else:
        seeds = get_seeds(crash_folder) 
    seeds = get_seeds_up_to(seeds, crash_id)
    seeds_orig = copy.deepcopy(seeds)
    no_progress = False
    while not no_progress:
        seeds_smaller = slice_seeds(seeds, minimizing_existing=minimizing_existing)
        reproduced_slices = []
        for seeds_try in seeds_smaller:
            seeds_try_chunks = split_seeds(seeds_try)
            crashed = run_cmd_seeds(device, service_obj, crash_file, seeds_try_chunks, iters=1)
            if crashed:
                reproduced_slices.append(seeds_try)
                do_log(f'reproduced slice. {len(seeds_try)}/{len(seeds)}')
                break
        if len(reproduced_slices) == 0:
            no_progress = True
            do_log(f'failed to reproduce crashes with minimizing...')
        else:
            seeds = min_merge_slices(reproduced_slices)
    do_log(f'reduced poc: {len(seeds)}/{len(seeds_orig)}')
    # write output poc
    seeds_split = split_seeds(seeds)
    env = f"NOSHM=1 DESER_PATH={TRIAGE_PATH}/deserializers_used.txt SERVICE_NAME={service_obj.service_name} INTERFACE_NAME={service_obj.onTransact.interface}"
    cmds = []
    open(seed_min_path, 'w+').write('\n'.join(seeds))
    for seeds in seeds_split:
        cmds.append(f"cd {TRIAGE_PATH} && {env} ./fuzzer {' '.join([s.remote_path for s in seeds])}") 
    cmds[-1] = cmds[-1] + f" {TRIAGE_CRASHES}/{crash_file}" 
    cmd_path = os.path.join(crash_folder, 'replay_min.sh')
    open(cmd_path, 'w+').write('\n'.join(cmds))

def setup_debugging(device, service, binder_db, meta_target=None):
    if meta_target is None:
        meta_target = device
    # setup folder for manual triaging
    service_obj = database.get_service(binder_db, service, meta_target)
    do_log('setting up on device')
    setup_device(device, service_obj, binder_db, meta_target=meta_target)
    triage_path = os.path.join(TARGET_DIR, device, service, "fuzz_out") 
    dedup_folder = os.path.join(triage_path, TRIAGE_FANS_DEDUP)
    if os.path.exists(dedup_folder):
        adb.push_privileged(dedup_folder, TRIAGE_CRASHES, device_id=device, is_directory=True)
        adb.execute_privileged_command(f'cp -r {TRIAGE_CRASHES}/deduplicated/*/data {TRIAGE_PATH}', device_id=device)
        adb.execute_privileged_command(f'cp {TRIAGE_CRASHES}/deduplicated/*/crash-* {TRIAGE_CRASHES}/', device_id=device)
        adb.execute_privileged_command(f'cd {TRIAGE_PATH} && for dir in ./crashes/deduplicated/*/; do folder=$(basename "$dir"); cp "$dir/replay.sh" "./replay_$folder.sh" && chmod +x "./replay_$folder.sh"; done', device_id=device)
        adb.execute_privileged_command(f'cd {TRIAGE_PATH} && for dir in ./crashes/deduplicated/*/; do folder=$(basename "$dir"); cp "$dir/replay_min.sh" "./replay_min_$folder.sh" && chmod +x "./replay_min_$folder.sh"; done', device_id=device)
    else:
        print(f'!! No deduplicated crashes exist!!')
    adb.push_privileged(os.path.join(BASE_DIR, "..", "tools", "gef.py"), os.path.join(TRIAGE_PATH, "gef.py"), device_id=device)

    # make archive
    adb.execute_privileged_command(f'cd /data/local/tmp && tar czf triage.tar.gz triage', device_id=device)
    adb.pull_privileged(f'/data/local/tmp/triage.tar.gz', os.path.join(dedup_folder, "triage.tar.gz"), device_id=device)

    env = f"NOSHM=1 DESER_PATH={TRIAGE_PATH}/deserializers_used.txt SERVICE_NAME={service_obj.service_name} INTERFACE_NAME={service_obj.onTransact.interface}"
    cmd = f"{env} ./fuzzer <crash_path>"

    print(f'adb -s {device} shell')
    print(f'su')
    print(f'cd {TRIAGE_PATH}')
    print(cmd)
    print('OR:')
    print(f'./replay_X.sh or ./replay_X_min.sh')
    print("=== Debugging ===")
    print(f'adb -s {device} shell')
    print(f'su')
    print(f'PATH=$PATH:/data/data/com.termux/files/usr/bin')
    print(f'gdb -ex "source /data/local/tmp/triage/gef.py" --pid $(dumpsys --pid {service_obj.service_name})')

def parse_path(path):
    output_paths = []
    path_parts = path.split("/")
    idx_targets = path_parts.index("targets")
    idx_fuzzout = path_parts.index("fuzz_out")
    idx_service_name_1 = idx_targets+2
    idx_service_name_2 = idx_fuzzout-1
    if idx_service_name_1 == idx_service_name_2:
        service = path_parts[idx_service_name_1]
    else:
        service = ""
        for i in range(idx_service_name_1, idx_service_name_2+1):
            service += path_parts[i] + "/"
        service = service[:-1]
    device = path_parts[idx_targets+1]
    output_paths.append(path_parts[idx_fuzzout+1])
    return device, service, output_paths, path_parts[-1]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=f'try reproducing crashed')
    parser.add_argument("-d", "--device",  type=str, required=False, help="Device")
    parser.add_argument("-s", "--service", type=str, required=False, help="service name")
    parser.add_argument("-t", "--triage", default=False, required=False, action="store_true", help="setup for manual triage on the device")
    parser.add_argument("-m", "--minimize", default=False, required=False, action="store_true", help="minimize a crash: path to dedup crash id folder /service/fuzz_out/deduplicated/id")
    parser.add_argument("--dont_rerun_reproduced", required=False, default=False, action="store_true", help="dont check if we already tried reproducing the crashes")
    parser.add_argument("--dont_rerun_non_reproduced", required=False, default=True, action="store_false", help="dont check if we already tried reproducing the crashes")
    parser.add_argument("-i", "--input_path", type=str, required=False, help="set specific path to input")

    args = parser.parse_args()

    service = None
    device = None
    output_paths = []
    if args.input_path is not None:
        device, service, output_paths, crash_id = parse_path(args.input_path)
        if args.device is not None:
            device = args.device
        if args.service is not None:
            service = args.service
    else:
        #TODO: support for meta device
        service = args.service
        device = args.device
        if META_TARGET is None:
            output_paths = [p for p in os.listdir(os.path.join(TARGET_DIR, device, service, "fuzz_out")) if p!=TRIAGE_FANS_DEDUP]
        else:
            output_paths = [p for p in os.listdir(os.path.join(TARGET_DIR, META_TARGET, service, "fuzz_out")) if p!=TRIAGE_FANS_DEDUP] 

    if args.triage:
        setup_debugging(device, service, binder_db)
    elif args.minimize:
        print(crash_id)
        do_minimize(device, service, crash_id)
    else:
        for out in output_paths:
            do_triage(device, service, out, meta_target=META_TARGET, dont_rerun_reproduced=args.dont_rerun_reproduced, rerun_non_reproduced=args.dont_rerun_non_reproduced)        






