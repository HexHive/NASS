import frida
import argparse
import subprocess
import threading
import os
import logging
import traceback
from collections import defaultdict
import sys
from datetime import datetime
import time
import json
import tempfile
import uuid
import itertools


BASE_DIR: str = os.path.dirname(__file__)
sys.path.append(os.path.join(BASE_DIR, ".."))
sys.path.append(os.path.join(BASE_DIR, "..", "fuzz"))
DEVICE_DIR = os.path.join(BASE_DIR, "..", "device")

from config import (
    BINDER_FUNCS,
    PHASE_1_SEED_DIRNAME,
    PHASE_2_SEED_DIRNAME,
    LIBRARY_BLOCKLIST,
    DRCOV_DIRNAME,
    SEEDSDRCOV,
    CUSTOM_DUMPSYS_PATH,
    NEED_CUSTOM_DUMPSYS,
    META_TARGET,
    IS_EMULATOR,
    FANS_NOVARMAP_FILE
)
import fuzzparcel
import service.vanilla as vanilla
import data.database as database
import emulator.emulator as emulator
import utils.utils as utils
import adb
from instrument.hook import ServiceHooker

RED = "\033[0;31m"
YELLOW = "\033[0;33m"
GREEN = "\033[0;32m"
NC = "\033[0m"
BLUE = "\033[0;34m"
PURPLE = "\033[0;35m"
CYAN = "\033[0;36m"

REFINE_FRIDA_SCRIPT = os.path.join(BASE_DIR, "fridajs", "refine.js")
DRCOV_FRIDA_SCRIPT = os.path.join(BASE_DIR, "fridajs", "drcov.js")

TIMEOUT = 10 * 60

REPLAY_PATH = "/data/local/tmp/fans-cov" # needs to be this for fans
PHASE1_SEED_PATH = os.path.join(REPLAY_PATH, PHASE_1_SEED_DIRNAME)
DATA_SEED_PATH = os.path.join(REPLAY_PATH, "data")
DESERIAL_USED_PATH = os.path.join(REPLAY_PATH, "deserializers_used.txt")
SEED_REPLAYS = 1
PID_PATH = os.path.join(REPLAY_PATH, ".pid")
PID_ACK_PATH = os.path.join(REPLAY_PATH, ".pid_ack")
DONE_PATH = os.path.join(REPLAY_PATH, ".replay_done")


logging.basicConfig(
    filename=os.path.join(BASE_DIR, "log", "fans-replay.log"),
    encoding="utf-8",
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(filename)s.%(funcName)s %(message)s",
    force=True,
)

"""
script that replays a seed corpus against the service to extract the drcov 
coverage map 
"""


def run_cmd(cmd):
    subprocess.check_output(cmd, shell=True)

class SeedBare:
    def __init__(self, file_path) -> None:
        self.file_path = file_path
        self.remote_path = None

class RecvDrcovData:
    def __init__(self, raw_json, data) -> None:
        self.data = data
        self.pid = raw_json["caller_pid"]
        self.bbs = raw_json["bbs"]


class RecvRefineData:
    def __init__(self, raw_json) -> None:
        self.typ = raw_json["type"]
        if self.typ == "onTransact_end":
            self.binderfunc = None
        else:
            self.binderfunc = raw_json["name"]
        self.pid = raw_json["pid"]
        self.call_counter = raw_json["call_counter"]

    def __str__(self) -> str:
        return f"RefineData({self.typ}, pid:{self.pid}, ctr:{self.call_counter}), func: {self.binderfunc}"

    def __repr__(self) -> str:
        return f"RefineData({self.typ}, pid:{self.pid}, ctr:{self.call_counter}), func: {self.binderfunc}"


class Interface:
    def __init__(self, code, nr_deserializers, interface_names) -> None:
        self.code = code
        self.all_deserializers = []
        self.known_deserializers =nr_deserializers *[None] 
        self.unknown_deserializers =nr_deserializers *[None] 
        self.interface_names = interface_names
    def add_arg(self, mangled_function, call_counter):
        demangled = utils.demangle_cpp(mangled_function)
        demangled = demangled.split("::")[-1]
        functype = utils.find_binder_func(BINDER_FUNCS, demangled)
        idx = len(self.all_deserializers)
        self.all_deserializers.append((functype, mangled_function))
        if functype is None:
            self.unknown_deserializers[call_counter - 1] = (
                functype,
                mangled_function,
            )
        else:
            self.known_deserializers[call_counter - 1] = (
                functype,
                mangled_function,
            )

    def size(self):
        return len(self.all_deserializers)

    def is_subset(self, other):
        # is other just a subset of the deserializers of self
        # other has the same deserialization functions in the same order but less
        # equal, is_subset
        for i, deser in enumerate(other.all_deserializers):
            if deser != self.all_deserializers[i]:
                return False, False
        if self.size() > i + 1:
            return True, True
        return True, False
    
    def to_parcelentry(self, functype, interface_name =None):
        type_enum = fuzzparcel.parcelfunc2type[functype]
        if type_enum == fuzzparcel.ParcelType.STRONGBINDER:
            # setup random binder entry
            if interface_name is not None:
                interface_name = interface_name.encode()
            else:
                interface_name = b"RandomBinder"
            reply_data = 0x10 * b"\x00"
            data = (len(interface_name)).to_bytes(4, "little")
            data += (len(reply_data)).to_bytes(4, "little")
            data += interface_name
            data += reply_data
            length = len(data)
        elif type_enum in fuzzparcel.fixed_length:
            length = fuzzparcel.fixed_length[type_enum]
            data = b"\x00" * length
        else:
            length = 0x8
            data = b"\x00" * length
        assert length != 0, "lenght is 0!!!"
        return fuzzparcel.ParcelEntry(type_enum, length, data)

    def to_fuzzparcels(self):
        # TODO: if we have interface names and multiple interface names,
        # generate all combinations
        entries_to_add = []
        strongbinder_entries = []
        idx = 0
        for functype, mangled in self.all_deserializers:
            if "readParcelable" in mangled:
                logging.warning(f'readParceable, skipping...')
                idx += 1
                continue
            if functype is None:
                logging.warning(
                    f"unknown None entry!, adding unknown entry!! {mangled}"
                )
                entries_to_add.append(("unknown", None))
                idx += 1
                continue
            entries_to_add.append((functype, mangled))
            if functype == 'readStrongBinder':
                strongbinder_entries.append(idx)
            idx += 1
        if len(self.interface_names) == 0 or len(strongbinder_entries) == 0:
            # no need to handle strongbinder stuff
            parcel = fuzzparcel.FuzzParcel(self.code, len(entries_to_add))
            for functype, mangled in entries_to_add:
                parcel_entry = self.to_parcelentry(functype)
                parcel.entries.append(parcel_entry)
            assert parcel.nr_entries == len(parcel.entries), f"{parcel}, {len(parcel.entries)}, {parcel.entries}"
            return [parcel]
        else:
            value_permutations = itertools.combinations(self.interface_names, len(strongbinder_entries))
            mappings = []
            for perm in value_permutations:
                mapping = dict(zip(strongbinder_entries, perm))
                mappings.append(mapping)
            logging.info(f'strongibnder entry mappings {mappings}')
            out = []
            for map in mappings:
                parcel = fuzzparcel.FuzzParcel(self.code, len(entries_to_add))
                for idx, (functype, mangled) in enumerate(entries_to_add):
                    if idx in map:
                        assert functype == 'readStrongBinder', f"{map}, idx: {idx} not matching with {functype}"
                        interface_name = map[idx]
                    parcel_entry = self.to_parcelentry(functype, interface_name=interface_name)
                    parcel.entries.append(parcel_entry)
                assert parcel.nr_entries == len(parcel.entries), f"{parcel}, {len(parcel.entries)}, {parcel.entries}"
                pass
                out.append(parcel)
            return out

    def to_json(self):
        return {
            "code": self.code,
            "all": self.all_deserializers,
            "unknown": self.unknown_deserializers,
            "known": self.known_deserializers,
            "SBInterfaces": self.interface_names,
        }

    def __str__(self) -> str:
        out = f"Interface(cmd:{self.code}, all: {self.all_deserializers}, unknown: {self.unknown_deserializers}, known: {self.known_deserializers}, SBInterfaces: {self.interface_names})"
        return out

    def __repr__(self) -> str:
        out = f"Interface(cmd:{self.code}, all: {self.all_deserializers}, unknown: {self.unknown_deserializers}, known: {self.known_deserializers}, SBInterfaces: {self.interface_names})"
        return out


def insert_interface_into_db(binder_db, service, interface: Interface):
    if interface is None:
        return
    interface_json = interface.to_json()
    database.insert_phase2_seed(
        binder_db, service.db_id, interface.code, interface_json
    )

def interface_from_json(raw_json):
    inter = Interface(raw_json["code"], len(raw_json["all"]))
    inter.all_deserializers = raw_json["all"]
    inter.known_deserializers = raw_json["known"]
    inter.unknown_deserializers = raw_json["unknown"]
    return inter

def generate_interface_definition(seed, messages, interface_names):
    # handle case if service crashes:
    interface = Interface(seed.code, len(messages), list(set(interface_names)))
    for msg in messages:
        if msg.typ == "onTransact_end":
            continue
        interface.add_arg(msg.binderfunc, msg.call_counter)
    return interface


class Replayer(ServiceHooker):
    def __init__(
        self, servicename, device, svc_obj, seed_path, binder_db, meta_device_id
    ) -> None:
        super().__init__(servicename, device, "vanilla", svc_obj, meta_device_id=meta_device_id)
        self.frida_ready = False
        self.action = None
        self.binder_db = binder_db
        self.seed_path = seed_path
        self.drcov_script = os.path.join(BASE_DIR, "..", "fuzz", "fridajs", "drcov.js") 
        self.ordered_seeds = []
        self.replay_messages = []
        self.pid2seed = {}
        self.deser_used = []
        self.all_bbs = []
        self.seed2bbs = {}
        self.seed2pid = defaultdict(list)
        self.interface_names = []
        fans_varmap_file = os.path.join(self.seed_path, FANS_NOVARMAP_FILE)
        if os.path.exists(fans_varmap_file):
            self.fans_novarmap = True
        else:
            self.fans_novarmap = False

    def log(self, line):
        print(f"[{self.action}][{self.device_id}] {line}")
        logging.info(f"[{self.device_id}] {line}")

    def frida_injected(self):
        if self.script is None:
            return False
        try:
            self.script.exports_sync.ping()
            return True
        except Exception as e:
            self.log(f"attempting to ping failed with: {str(e)}")
            return False

    def setup_device(self):
        if not adb.path_exists(REPLAY_PATH, device_id=self.device_id):
            _, err = adb.execute_privileged_command(
                f"mkdir -p {REPLAY_PATH}", device_id=self.device_id
            )
            if err:
                self.log(f"ERROR, unable to create {REPLAY_PATH}")
                exit(-1)
        else:
            adb.execute_privileged_command(
                f"rm -rf {REPLAY_PATH}/*", device_id=self.device_id
            )
        fuzzer_path = os.path.join(DEVICE_DIR, self.meta_device_id, "fuzzer")
        if not os.path.exists(fuzzer_path):
            self.log(f"fuzzer not compiled: {fuzzer_path} does not exist")
            raise Exception
        fuzzer_remote_path = os.path.join(
            REPLAY_PATH, os.path.basename(fuzzer_path)
        )
        if not adb.path_exists(fuzzer_remote_path, device_id=self.device_id):
            adb.push_privileged(
                fuzzer_path, fuzzer_remote_path, device_id=self.device_id
            )
        tmp_deser_used = database.dump_used_deser(
            self.binder_db, self.service.db_id
        )
        adb.push_privileged(
            tmp_deser_used, DESERIAL_USED_PATH, device_id=self.device_id
        )
        os.system(f"rm -rf {tmp_deser_used}")
        adb.execute_privileged_command(
            f"chmod 777 {REPLAY_PATH}", device_id=self.device_id
        )
        # fans shit
        if self.fans_novarmap:
            self.fans_fuzzer = "native_service_fuzzer_coverage_novarmap"
        else:
            self.fans_fuzzer = "native_service_fuzzer_coverage"
        fuzzer_path = os.path.join(BASE_DIR, self.fans_fuzzer)
        if not os.path.exists(fuzzer_path):
            self.log(f"fuzzer not compiled! {fuzzer_path}")
            raise Exception
        fuzzer_remote_path = os.path.join(
            REPLAY_PATH, os.path.basename(fuzzer_path)
        )
        if not adb.path_exists(fuzzer_remote_path, device_id=self.device_id):
            adb.push_privileged(
                fuzzer_path, fuzzer_remote_path, device_id=self.device_id
            )
        adb.push_privileged(
            os.path.join(BASE_DIR, 'seed'), REPLAY_PATH, is_directory=True, 
            device_id=self.device_id
            )
        adb.push_privileged(
            os.path.join(BASE_DIR, 'workdir/interface-model-extractor/model'), 
            REPLAY_PATH, is_directory=True, device_id=self.device_id
            )
        adb.push_privileged(
            os.path.join(BASE_DIR, 'fuzzer-engine/fuzzer-coverage'), REPLAY_PATH, 
                         is_directory=True, device_id=self.device_id
            )
        if IS_EMULATOR:
            # FANS comparison stuff, testing apk file
            adb.push_privileged(os.path.join(BASE_DIR, "..", "tools", "example_apk", "test.apk"),
                                "/data/local/tmp",
                                device_id=self.device_id)

    def upload_seeds(self, remote_seed_dir):
        if adb.path_exists(remote_seed_dir, device_id=self.device_id):
            adb.execute_privileged_command(
                f"rm -rf {remote_seed_dir}", device_id=self.device_id
            )
        else:
            adb.execute_privileged_command(
                f"mkdir -p {remote_seed_dir}", device_id=self.device_id
            )
        for seed in self.ordered_seeds:
            remote_seed = os.path.join(
                remote_seed_dir, os.path.basename(seed.file_path)
            )
            seed.remote_path = remote_seed
        assert (
            os.path.basename(remote_seed_dir) == "data"
        ), "uploading \
            seeds not from data dir"
        adb.push_privileged(
            os.path.join(self.seed_path, "data"),
            REPLAY_PATH,
            device_id=self.device_id,
            is_directory=True,
        )

    def setup_replay(self, remote_seed_dir):
        # setup refine folder on the device
        self.log("setting up device")
        self.setup_device()
        # upload the seeds for replay
        self.log("uploading seeds")
        self.upload_seeds(remote_seed_dir)
        # set deserialization functions
        deser_used = database.get_used_deser_mangled(
            self.binder_db, self.service.db_id
        )
        for deser_func in deser_used:
            self.deser_used.append(deser_func)
        self.log(f"used deserializers: {self.deser_used}")

    def pull_pid(self):
        if not adb.path_exists(PID_PATH, device_id=self.device_id):
            self.log('ERROR WTFFFFF pulling pid but path does not exist?!?')
            return
        out, err = adb.execute_privileged_command(
            f"cat {PID_PATH}", device_id=self.device_id
        )
        if len(err) > 0:
            self.log(f"ERROR in pid pulling! {err}")
        try:
            out = int(out.decode())
            return out
        except ValueError:
            return None

    def do_replay_fans(self, seed):
        self.log(
            f"replaying seed({seed.file_path})"
            )
        adb.execute_privileged_command(
            f"rm {PID_PATH}", device_id=self.device_id
        )
        adb.execute_privileged_command(
            f"rm {PID_ACK_PATH}", device_id=self.device_id
        )
        adb.execute_privileged_command(
            f"rm {DONE_PATH}", device_id=self.device_id
        )
        adb.execute_privileged_command(
            f'pkill {self.fans_fuzzer}', device_id=self.device_id
        )
        env = f"NOSHM=1"
        cmd = f"cd {REPLAY_PATH} && {env} ./{self.fans_fuzzer} --replay_seed {seed.remote_path} > {REPLAY_PATH}/log.txt"
        out, err = adb.execute_privileged_command(
            cmd, device_id=self.device_id, wait_for_termination=False
        )
        # logging.debug(f'replaying of seed: {out}, {err}')
        pid = None
        tries = 0
        while not adb.path_exists(PID_PATH, device_id=self.device_id):
            if tries > 10:
                self.log(f"exceeded time waiting for .pid")
                break
            time.sleep(0.5)
            self.log(f"waiting for .pid")
            tries += 1
        pid = self.pull_pid()
        if pid is None:
            self.log(f"failed decoding .pid..")
        else:
            self.log(
                f"replaying seed ({seed}), adding to pid2seed with pid: {pid}"
            )
            self.pid2seed[pid] = seed
            self.seed2pid[seed].append(pid)
            while not adb.path_exists(DONE_PATH, device_id=self.device_id):
                if not adb.is_pid_running(pid, device_id=self.device_id):
                    if not adb.path_exists(DONE_PATH, device_id=self.device_id):
                        self.log("fuzzer exited but failed to set .done")
                        break
                    else:
                        break
                time.sleep(0.5)
                self.log("waiting for .done...")
        adb.execute_privileged_command(
            f"rm {PID_PATH}", device_id=self.device_id
        )
        adb.execute_privileged_command(
            f"rm {PID_ACK_PATH}", device_id=self.device_id
        )
        adb.execute_privileged_command(
            f"rm {DONE_PATH}", device_id=self.device_id
        )

    def do_replay_nass(self, seed):
        adb.execute_privileged_command(
            f"rm {PID_PATH}", device_id=self.device_id
        )
        adb.execute_privileged_command(
            f"rm {PID_ACK_PATH}", device_id=self.device_id
        )
        env = f"NOSHM=1 DESER_PATH={REPLAY_PATH}/deserializers_used.txt SERVICE_NAME={self.service.service_name} INTERFACE_NAME={self.service.onTransact.interface}"
        cmd = f"cd {REPLAY_PATH} && {env} ./fuzzer {seed.remote_path}"
        out, err = adb.execute_privileged_command(
            cmd, device_id=self.device_id, wait_for_termination=False
        )
        # logging.debug(f'replaying of seed: {out}, {err}')
        pid = None
        tries = 0
        while not adb.path_exists(PID_PATH, device_id=self.device_id):
            if tries > 10:
                self.log(f"exceeded time waiting for .pid")
                break
            time.sleep(0.5)
            self.log(f"waiting for .pid")
            tries += 1
        pid = self.pull_pid()
        if pid is None:
            self.log(f"failed decoding .pid..")
        else:
            self.log(
                f"replayed seed({seed}), adding to pid2seed with pid: {pid}"
            )
            self.pid2seed[pid] = seed
            self.seed2pid[seed].append(pid)
        adb.execute_privileged_command(
            f"rm {PID_PATH}", device_id=self.device_id, timeout=20
        )
        adb.execute_privileged_command(
            f"rm {PID_ACK_PATH}", device_id=self.device_id, timeout=20
        )

    def parse_seeds(self, data_dir, fuzzer):
        if not os.path.exists(data_dir):
            self.log(f"seed output directory: {data_dir} does not exist")
            return
        if len(os.listdir(data_dir)) == 0:
            self.log(f"no seeds in the data directory {data_dir}")
            return
        raw_list = []
        if fuzzer == "fans":
            seed_files = os.listdir(data_dir)
            for f in seed_files:
                if f.endswith(".rng"):
                    continue
                if os.path.isdir(os.path.join(data_dir, f)):
                    continue
                if not os.path.exists(os.path.join(data_dir, f'{f}.rng')):
                    continue
                iteration, sha1, timestamp = f.split("-")
                timestamp = int(timestamp)
                iteration = int(iteration)
                raw_list.append((iteration, timestamp, f))
            ordered_data_seeds = [d[2] for d in sorted(raw_list, key=lambda x: (x[1], x[0]))]
            for s in ordered_data_seeds:
                self.ordered_seeds.append(SeedBare(os.path.join(data_dir, s)))
        elif fuzzer == "nass":
            try:
                start_time = int(open(os.path.join(self.seed_path, "start_time.txt")).read())
            except:
                start_time = 0
            # move seeds to data dir so they also get replayed
            for root, _, files in os.walk(data_dir):
                if "final" not in root:
                    continue
                for f in files:
                    seed_path = os.path.join(root, f)
                    timestamp = start_time+1
                    iteration = 0
                    sha1 = f.split("-")[-1]
                    new_name = f"{iteration}-{sha1}-{timestamp}"
                    self.log(f"adding seed {seed_path} to data {new_name}")
                    run_cmd(f'cp {seed_path} {os.path.join(data_dir, new_name)}')
                    continue
            seed_files = os.listdir(data_dir)
            for f in seed_files:
                if f.startswith("seed-"):
                    continue
                if os.path.isdir(os.path.join(data_dir, f)):
                    continue
                iteration, sha1, timestamp = f.split("-")
                timestamp = int(timestamp)
                iteration = int(iteration)
                raw_list.append((iteration, timestamp, f))
            ordered_data_seeds = [d[2] for d in sorted(raw_list, key=lambda x: (x[1], x[0]))]
            for s in ordered_data_seeds:
                self.ordered_seeds.append(SeedBare(os.path.join(data_dir, s)))
        else:
            print("unknown fuzzer!!", fuzzer)
            exit(-1)

    ############################################################################
    # Drcov
    ############################################################################

    def drcov(self, fuzzer):
        # replay seeds and extract drcov (replay all seeds in data directory)
        if fuzzer == "fans":
            self.do_replay = self.do_replay_fans
        elif fuzzer == "nass":
            self.do_replay = self.do_replay_nass
        else:
            print("unknown fuzzer!!")
            exit(-1)
        data_dir = os.path.join(self.seed_path, "data")
        self.parse_seeds(data_dir, fuzzer)
        self.setup_replay(DATA_SEED_PATH)
        for seed in self.ordered_seeds:
            tries = 0
            max_tries = 3
            while tries < max_tries:
                success = self.drcov_replay_seed(seed, fuzzer)
                if not success:
                    tries += 1
                    self.setup_replay(DATA_SEED_PATH)
                    continue
                self.extract_bbs(seed)
                self.dump_seed_cov(seed)
                self.replay_messages = []  # clear messages from pipeline
                break
        self.dump_drcov()

    def on_message_drcov(self, message, data):
        self.log(f"on_message: {message}")
        if message["type"] == "send":
            payload = json.loads(message["payload"])
            payload_type = payload["type"]
            if payload_type == "setup_done":
                self.frida_ready = True
            elif payload_type == "bbs":
                parsed_message = RecvDrcovData(payload, data)
                self.replay_messages.append(parsed_message)
            elif payload_type == "maps":
                self.drcov_maps = payload["map"]
            else:
                self.log(f"message received: {payload}, {data}")
                # parsed_message = RecvDrcovData(payload)
                # self.replay_messages.append(parsed_message)

    def drcov_replay_seed(self, seed, fuzzer):
        # return True if success
        # return False if failed
        try:
            if not self.service.check_service():
                # wait for service to come back up
                self.log("waiting for service to come back")
                self.service.wait_for_service()
            if not self.frida_injected():
                # inject frida script
                self.log("loading frida script")
                self.setup_script(self.drcov_script, self.on_message_drcov)
                self.script.load()
                while not self.frida_ready:
                    self.log("waiting for frida script to come up...")
                    time.sleep(1)
                # set onTransact binary
                self.script.exports_sync.setontransact(
                    self.service.onTransact.entry_addr,
                    os.path.basename(self.service.onTransact.bin),
                    self.service.onTransact.BBinder_path,
                )
                # setup coverage exclusions
                for lib in self.get_ranges_to_instrument():
                    code_range = self.service.proc_map.get_vmabyname(lib)
                    if code_range is None:
                        self.log(f"weird, code range not inside: {code_range}")
                        continue
                    self.log(f"adding bin to instrument: {code_range.vma_name}")
                    self.script.exports_sync.addrange(code_range.vma_name)
                # enabling pid filter to filter all requests
                self.drcov_set_pid(0)
                # start instrumentation
                self.script.exports_sync.instrument()
            # caller = threading.Thread(target=self.do_replay, args=[seed], kwargs={'pid_ack_callback': self.drcov_set_pid})
            adb.clear_logcat(device_id=self.device_id)
            caller = threading.Thread(target=self.do_replay, args=[seed,])
            caller.start()
            caller.join()
            if not self.service.check_service() or not self.frida_injected():
                if 'Unable to allocate code slab near' in adb.logcat_crashlog(device_id=self.device_id):
                    if IS_EMULATOR:
                        emulator.reset(self.device_id)
                    adb.wait_for_device(self.device_id) 
                    return False
            return True
        except adb.ADBDeviceOffline as e:
            self.log(f"adb.ADBDeviceOffline during replay_seed: {str(e)}")
            if IS_EMULATOR:
                emulator.reset(self.device_id)
            adb.wait_for_device(self.device_id)
            return False 
        except adb.ADBDeviceNotFound as e:
            self.log(f"ADBeviceNotFound during replay_seed: {str(e)}")
            if IS_EMULATOR:
                emulator.reset(self.device_id)
            adb.wait_for_device(self.device_id)
            return False
        except adb.ADBTimeoutException as e:
            self.log(f"TimeoutError while witing for service {str(e)}")
            if IS_EMULATOR:
                emulator.reset(self.device_id)
            else:
                adb.reboot(device_id=self.device_id)
            adb.wait_for_device(self.device_id)
            return False
        except Exception as e:
            self.log(f"unkown error, doing more resetting {str(e)}")
            if IS_EMULATOR:
                emulator.reset(self.device_id)
            else:
                adb.reboot(device_id=self.device_id)
            adb.wait_for_device(self.device_id)
            return False


    def drcov_set_pid(self, fuzzer_pid):
        self.log(f"setting pid filter to {fuzzer_pid}")
        self.script.exports_sync.filterpids(fuzzer_pid)

    def get_ranges_to_instrument(self):
        service_binary = os.path.basename(self.service.binary_path)
        onTransact_binary = os.path.basename(self.service.onTransact.bin)
        libs = self.service.get_dependencies()
        if onTransact_binary in libs:
            # if onTransact functionality is in the service binary, remove the binary from the list
            # we add the onTransact binary for coverage anyways so this way we can avoid it to be twice in the list
            libs.remove(onTransact_binary)
        # TODO maybe add a custom config.py
        libs = utils.remove_blocklist(libs, LIBRARY_BLOCKLIST)
        logging.info(f"libraries to instrument: {libs}")
        return libs

    def extract_bbs(self, seed):
        messages = [
            m for m in self.replay_messages if m.pid in self.seed2pid[seed]
        ]
        block_sz = 8
        seed_bbs = set([])
        if len(messages) > 1:
            self.log('STRANGE more than 1 drcov messages...')
            messages = [messages[-1]] # FANS HACK, we know the final transaction should be ours
        for m in messages:
            for i in range(0, len(m.data), block_sz):
                seed_bbs.add(m.data[i : i + block_sz])
                self.all_bbs.append(m.data[i : i + block_sz])
        self.seed2bbs[seed] = seed_bbs

    def dump_seed_cov(self, seed):
        if seed not in self.seed2bbs:
            return
        drcov_out = os.path.join(self.seed_path, DRCOV_DIRNAME)
        if not os.path.exists(drcov_out):
            run_cmd(f"mkdir -p {drcov_out}")
        seed_drcov_dir = os.path.join(drcov_out, SEEDSDRCOV)
        if not os.path.exists(seed_drcov_dir):
            run_cmd(f'mkdir -p {seed_drcov_dir}')
        drcov_out = os.path.join(
            seed_drcov_dir, f'{os.path.basename(seed.file_path)}.drcov'
        )
        self.log(f"dumping single seed cov: {drcov_out}")
        bbs = self.seed2bbs[seed] 
        self.modid2path = {}
        self.modid2mod = {}
        for m in self.drcov_maps:
            self.modid2path[m['id']] = m['path']
            self.modid2mod[m['id']] = m 
        self.save_coverage(drcov_out, bbs)

    def dump_drcov(self):
        self.modid2path = {}
        self.modid2mod = {}
        for m in self.drcov_maps:
            self.modid2path[m['id']] = m['path']
            self.modid2mod[m['id']] = m
        # write drcov output directory
        # filter for caller pid
        drcov_out = os.path.join(self.seed_path, DRCOV_DIRNAME)
        self.log(f"dumping drcov to direcotry: {drcov_out}")
        if not os.path.exists(drcov_out):
            run_cmd(f"mkdir -p {drcov_out}")
        out_path = os.path.join(drcov_out, "merged-cov.log")
        self.save_coverage(out_path, self.all_bbs)
        self.modid2bbs = defaultdict(list)
        for bb in self.all_bbs:
            start, size, mod_id = self.parse_bb(bb)
            self.log(f"{hex(start)}, {mod_id}")
            self.modid2bbs[mod_id].append(bb)
        for mod_id, bbs in self.modid2bbs.items():
            rel_mod = self.modid2mod[mod_id]
            out_path = os.path.join(
                drcov_out,
                os.path.basename(self.modid2path[mod_id]) + "-cov.txt",
            )
            self.save_coverage(
                out_path, 
                bbs, 
                {'id': mod_id, 
                    'base': rel_mod['base'], 
                    'end': rel_mod['end'], 
                    'path': rel_mod['path']
                }
            )
        self.dump_covered_libs()

    def dump_covered_libs(self):
        mod_ids = set()
        for bb in self.all_bbs:
            start, size, mod_id = self.parse_bb(bb)
            mod_ids.add(mod_id)
        covered_libs = []
        for mod_id in list(mod_ids):
            name = None
            for m in self.drcov_maps:
                if m["id"] == mod_id:
                    name = m["path"]
            if name is not None:
                covered_libs.append(name)
        self.log(f'covered libraries: {",".join(covered_libs)}')
        drcov_out = os.path.join(self.seed_path, DRCOV_DIRNAME)
        open(os.path.join(drcov_out, "covered_bins.txt"), "w+").write(
            "\n".join(covered_libs)
        )
        for lib in covered_libs:
            local_path = os.path.join(
                self.service.local_path, os.path.basename(lib)
            )
            if not os.path.exists(local_path):
                self.log(f"downloading: {lib}")
                adb.pull_privileged(lib, local_path, device_id=self.device_id)

    def parse_bb(self, bb):
        """
        typedef struct _bb_entry_t {
            uint   start;      // offset of bb start from the image base
            ushort size;
            ushort mod_id;
        } bb_entry_t;
        """
        start = int.from_bytes(bb[:4], "little")
        size = int.from_bytes(bb[4:6], "little")
        mod_id = int.from_bytes(bb[6:8], "little")
        return start, size, mod_id

    def save_coverage(self, out_path, bbs, spec_map=None):
        header = self.create_header(spec_map=spec_map)
        body = self.create_coverage(bbs)
        with open(out_path, "wb+") as h:
            h.write(header)
            h.write(body)

    def create_coverage(self, data):
        bb_header = b"BB Table: %d bbs\n" % len(data)
        return bb_header + b"".join(data)

    def create_header(self, spec_map=None):
        header = ""
        header += "DRCOV VERSION: 2\n"
        header += "DRCOV FLAVOR: frida\n"
        if spec_map is None:
            header += "Module Table: version 2, count %d\n" % len(
                self.drcov_maps
            )
        else:
            header += "Module Table: version 2, count %d\n" % 1
        header += "Columns: id, base, end, entry, checksum, timestamp, path\n"
        entries = []
        if spec_map is not None:
            entry = "%3d, %#016x, %#016x, %#016x, %#08x, %#08x, %s" % (
                spec_map["id"],
                int(spec_map["base"], 16),
                int(spec_map["end"], 16),
                0,
                0,
                0,
                spec_map["path"],
            )
            entries.append(entry)
        else:
            for m in self.drcov_maps:
                # drcov: id, base, end, entry, checksum, timestamp, path
                # frida doesnt give us entry, checksum, or timestamp
                #  luckily, I don't think we need them.
                entry = "%3d, %#016x, %#016x, %#016x, %#08x, %#08x, %s" % (
                    m["id"],
                    int(m["base"], 16),
                    int(m["end"], 16),
                    0,
                    0,
                    0,
                    m["path"],
                )
                entries.append(entry)
        header_modules = "\n".join(entries)
        return ("%s%s\n" % (header, header_modules)).encode("utf-8")


if __name__ == "__main__":

    ############################################################################
    # set up argument parser
    ############################################################################

    parser = argparse.ArgumentParser(
        description=f"Replay seeds against a service to refine seeds or extract \
        drcov coverage"
    )
    parser.add_argument(
        "fuzzer",
        type=str,
        choices=["fans", "nass"],
        help="choose fuzzer which generated the seeds in question",
    )
    parser.add_argument(
        "-s",
        "--service_name",
        type=str,
        required=True,
        help="name of native service",
    )
    parser.add_argument(
        "-d", "--device", type=str, required=True, help="device to test"
    )
    parser.add_argument(
        "-f",
        "--file_path",
        type=str,
        required=True,
        help="specify path to fuzzing run output directory",
    )
    args = parser.parse_args()

    ############################################################################
    # sanity check + start emulator
    ############################################################################

    if IS_EMULATOR:
            print(f'[ORC] emulator starting up')
            emulator.full_reset(args.device)
    if args.device not in adb.get_device_ids():
        print(f'{RED} device {args.device} not connected')
        exit(-1)

    ############################################################################
    # sanity check before starting
    ############################################################################

    if not os.path.exists(os.path.join(args.file_path, "data")):
        print(
            f"{RED}{args.file_path}/data does not exist, cannot proceed without seeds..{NC}"
        )
        exit(-1)

    ############################################################################
    # custom dumpsys handling
    ############################################################################

    if NEED_CUSTOM_DUMPSYS and \
        not adb.path_exists(CUSTOM_DUMPSYS_PATH, device_id=args.device):
        remote_path = os.path.dirname(CUSTOM_DUMPSYS_PATH)
        adb.execute_privileged_command(
            f"mkdir -p {remote_path}", device_id=args.device
        )
        if META_TARGET is None:
            path_to_dumpsys = os.path.join(
                BASE_DIR, "..", "device", args.device, "dumpsys"
            )
        else:
            path_to_dumpsys = os.path.join(
                BASE_DIR, "..", "device", META_TARGET, "dumpsys"
            )
        adb.push_privileged(path_to_dumpsys, remote_path, device_id=args.device)

    ############################################################################
    # reset the device
    ############################################################################

    print("[REF] resetting device, killing service and waiting for device")
    adb.reset_service(args.service_name, args.device)
    print("[REF] finished reset, continuing")

    ############################################################################
    # select device to fuzz on
    ############################################################################

    devices = frida.enumerate_devices()
    possible_devices = [d for d in devices if d.type == "usb"]
    possible_devices = [
        d for d in possible_devices if not "ios" in d.name.lower()
    ]
    device = None
    if args.device is not None:
        if args.device not in [d.id for d in possible_devices]:
            print(f"{RED}[-] device not connected!{NC}")
            print(
                f"connected devices: ",
                ",".join([d.id for d in possible_devices]),
            )
        else:
            device = [d for d in possible_devices if d.id == args.device][0]
    else:
        if len(possible_devices) == 1:
            device = possible_devices[0]
        else:
            print(
                f"{RED}[-] device not specified but multiple devices connected{NC}"
            )
            print(
                f"connected devices: ",
                ",".join([d.id for d in possible_devices]),
            )
    if device is None:
        exit(-1)

    ############################################################################
    # retrieve target service info obtained from pre-processing
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
    # start replaying 
    ############################################################################

    rep = Replayer(args.service_name, device, svc, args.file_path, binder_db, meta_device_id=META_TARGET)
    rep.drcov(args.fuzzer)
