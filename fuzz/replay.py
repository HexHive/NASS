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

from config import (
    DEVICE_DIR,
    BINDER_FUNCS,
    PHASE_1_SEED_DIRNAME,
    PHASE_2_SEED_DIRNAME,
    LIBRARY_BLOCKLIST,
    DRCOV_DIRNAME,
    PHASE_1_BACKUP_DATA,
    BINDERFUNCSWRAPPER,
    NEED_CUSTOM_DUMPSYS,
    IS_EMULATOR,
    META_TARGET,
    BINDER_KNOWN_CMDS
)
import fuzzparcel
import service.vanilla as vanilla
import data.database as database
import utils.utils as utils
import emulator.emulator as emulator
import adb
from instrument.hook import ServiceHooker
from triage import parse_path

MAX_ENTRIES = 100

NON_NULL_VALUE = 0x400

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

REPLAY_PATH = "/data/local/tmp/replay"
PHASE1_SEED_PATH = os.path.join(REPLAY_PATH, PHASE_1_SEED_DIRNAME)
DATA_SEED_PATH = os.path.join(REPLAY_PATH, "data")
DESERIAL_USED_PATH = os.path.join(REPLAY_PATH, "deserializers_used.txt")
SEED_REPLAYS = 1
PID_PATH = os.path.join(REPLAY_PATH, ".pid")
PID_ACK_PATH = os.path.join(REPLAY_PATH, ".pid_ack")


logging.basicConfig(
    filename=os.path.join(BASE_DIR, "log", "refine.log"),
    encoding="utf-8",
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(filename)s.%(funcName)s %(message)s",
    force=True,
)

"""
script that replays a seed corpus against the service to extract the refined
interface definition
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
        self.is_leave = False
        self.is_parcebleArraySize = False # track special type
        self.is_parcebleArrayEntry = False
        if self.typ == "onTransact_end":
            self.binderfunc = None
        else:
            self.binderfunc = raw_json["name"]
        if self.typ == "Binderfunc_exit":
            self.is_leave = True
        if self.typ == "readParcelableArray":
            self.binderfunc = "AParcel_readParcelableArray" 
        if self.typ == "readParcelableArray_exit":
            self.binderfunc = "AParcel_readParcelableArray"  
            self.is_leave = True
        if self.typ == "AParcel_setDataPosition":
            self.binderfunc = "AParcel_setDataPosition"
        self.pid = raw_json["pid"]
        self.call_counter = raw_json["call_counter"]

    def is_readInt32(self):
        return self.binderfunc is not None and "Parcel9readInt32" in self.binderfunc

    def is_readParceableArray(self):
        return self.binderfunc == "AParcel_readParcelableArray" and not self.is_leave 

    def is_readParceableArrayEnd(self):
        return self.binderfunc == "AParcel_readParcelableArray" and self.is_leave  

    def is_unsafeReadTypedVector(self):
        return self.binderfunc == "unsafeReadTypedVector" and not self.is_leave

    def is_unsafeReadTypedVectorEnd(self):
        return self.binderfunc == "unsafeReadTypedVector" and self.is_leave

    def is_setDataPosition(self):
        return self.binderfunc == "AParcel_setDataPosition"

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
    def add_arg(self, mangled_function, call_counter, idx, 
                isParcebleSize, isParceble):
        if isParcebleSize:
            functype = "readInt32ParcebleSize"
            mangled_function = "ParcebleSizeInt32"
        else:
            demangled = utils.demangle_cpp(mangled_function)
            demangled = demangled.split("::")[-1]
            functype = utils.find_binder_func(BINDER_FUNCS, demangled)
        self.all_deserializers.append((functype, mangled_function, isParceble))
        if functype is None:
            self.unknown_deserializers[idx] = (
                functype,
                mangled_function,
                isParceble
            )
        else:
            self.known_deserializers[idx] = (
                functype,
                mangled_function,
                isParceble
            )

    def size(self):
        return len(self.all_deserializers)

    def crop(self):
        self.known_deserializers = self.known_deserializers[:MAX_ENTRIES]
        self.unknown_deserializers = self.unknown_deserializers[:MAX_ENTRIES]
        self.all_deserializers = self.all_deserializers[:MAX_ENTRIES]

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
    
    def to_parcelentry(self, functype, interface_name =None, non_null=False):
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
        elif type_enum == fuzzparcel.ParcelType.INT32PARCEABLEARRAYLEN:
            # array length is 1
            length = fuzzparcel.fixed_length[type_enum] 
            data = 0x1.to_bytes(length, "little")
        elif type_enum in fuzzparcel.fixed_length:
            length = fuzzparcel.fixed_length[type_enum]
            if non_null:
                if (2**(8*length))-1 < NON_NULL_VALUE:
                    data = ((2**(8*length))-1).to_bytes(length, "little")
                else:
                    data = NON_NULL_VALUE.to_bytes(length, "little")
            else:
                data = b"\x00" * length
        elif type_enum in fuzzparcel.var_length:
            length = 0x8
            if non_null:
                data = b"\x20" * length
            else:
                data = b"\x00" * length
        elif type_enum in fuzzparcel.array_type:
            array_size = 0x8
            if non_null:
                if (2**(8*fuzzparcel.arr_type_size[type_enum])) -1 < NON_NULL_VALUE:
                    entry_data = ((2**(8*fuzzparcel.arr_type_size[type_enum])) -1).to_bytes(fuzzparcel.arr_type_size[type_enum], "little")
                else:
                    entry_data = NON_NULL_VALUE.to_bytes(fuzzparcel.arr_type_size[type_enum], "little")
                data = entry_data * array_size
            else:
                data = (b"\x00" * fuzzparcel.arr_type_size[type_enum]) * array_size
        elif type_enum in fuzzparcel.array_type_var_length:
            array_size = 0x1
            array_entry_size = 0x8
            data = array_size.to_bytes(4, "little")
            data += (array_size*array_entry_size).to_bytes(4, "little")
            for _ in range(0, array_size):
                data += array_entry_size.to_bytes(4, "little")
                if non_null:
                    data += b"\x20" * array_entry_size
                else:
                    data += b"\x00" * array_entry_size
            print(data.hex())
        else:
            if non_null:
                data = b"\x20" * 8 
            else:
                data = b"\x00" * 8
        data_length = len(data)
        assert data_length != 0, "lenght is 0!!!"
        return fuzzparcel.ParcelEntry(type_enum, data_length, data)

    def to_fuzzparcels(self):
        # TODO: if we have interface names and multiple interface names,
        # generate all combinations
        if self.size() > MAX_ENTRIES:
            # somethings fucked, let's not generate seeds that crash the fuzzer
            return []
        entries_to_add = []
        strongbinder_entries = []
        idx = 0
        for functype, mangled, isParceableEntry in self.all_deserializers:
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
            out = []
            parcel = fuzzparcel.FuzzParcel(self.code, len(entries_to_add))
            for functype, mangled in entries_to_add:
                parcel_entry = self.to_parcelentry(functype)
                parcel.entries.append(parcel_entry)
            assert parcel.nr_entries == len(parcel.entries), f"{parcel}, {len(parcel.entries)}, {parcel.entries}"
            out.append(parcel)
            parcel = fuzzparcel.FuzzParcel(self.code, len(entries_to_add))
            for functype, mangled in entries_to_add:
                parcel_entry = self.to_parcelentry(functype, non_null=True)
                parcel.entries.append(parcel_entry)
            assert parcel.nr_entries == len(parcel.entries), f"{parcel}, {len(parcel.entries)}, {parcel.entries}" 
            out.append(parcel)
            return out
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
                    interface_name = None
                    if idx in map:
                        assert functype == 'readStrongBinder', f"{map}, idx: {idx} not matching with {functype}"
                        interface_name = map[idx]
                    parcel_entry = self.to_parcelentry(functype, interface_name=interface_name)
                    parcel.entries.append(parcel_entry)
                assert parcel.nr_entries == len(parcel.entries), f"{parcel}, {len(parcel.entries)}, {parcel.entries}"
                pass
                out.append(parcel)
            for map in mappings:
                parcel = fuzzparcel.FuzzParcel(self.code, len(entries_to_add))
                for idx, (functype, mangled) in enumerate(entries_to_add):
                    interface_name = None
                    if idx in map:
                        assert functype == 'readStrongBinder', f"{map}, idx: {idx} not matching with {functype}"
                        interface_name = map[idx]
                    parcel_entry = self.to_parcelentry(functype, interface_name=interface_name, non_null=True)
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
    for i, msg in enumerate(messages):
        if msg.typ == "onTransact_end":
            continue
        interface.add_arg(msg.binderfunc, msg.call_counter, i, 
                          msg.is_parcebleArraySize, 
                          msg.is_parcebleArrayEntry)
    return interface

def mangled2functype(mangled):
    demangled = utils.demangle_cpp(mangled)
    demangled = demangled.split("::")[-1]
    functype = utils.find_binder_func(BINDER_FUNCS, demangled) 
    return functype



class Replayer(ServiceHooker):
    def __init__(
        self, servicename, device, svc_obj, seed_path, binder_db, meta_device_id=None
    ) -> None:
        super().__init__(servicename, device, "vanilla", svc_obj, meta_device_id=meta_device_id)
        self.frida_ready = False
        self.action = None
        self.binder_db = binder_db
        self.seed_path = seed_path
        self.refine_script = REFINE_FRIDA_SCRIPT
        self.drcov_script = DRCOV_FRIDA_SCRIPT
        self.data_seeds = []
        self.ordered_seeds = []
        self.replay_messages = []
        self.pid2seed = {}
        self.deser_used = []
        self.all_bbs = []
        self.seed2bbs = {}
        self.seed2pid = defaultdict(list)
        self.interface_names = []

    def log(self, line):
        print(f"[{self.action}][{self.device_id}] {line}")
        logging.info(f"[{self.device_id}] {line}")

    def prune_extra_calls(self, messages: list[RecvRefineData]):
        # iterate over messages 
        messages_pruned = []
        offset = 0
        self.log(f'pruning messages from {len(messages)} messages')
        while(offset < len(messages)):
            m = messages[offset]
            demangled = utils.demangle_cpp(m.binderfunc)
            demangled = demangled.split("::")[-1]
            functype = utils.find_binder_func(BINDER_FUNCS, demangled)
            if functype in BINDERFUNCSWRAPPER:
                
                messages_pruned.append(m)
                self.log(f'found wrapping binderfunction, starting pruning: {m}, offset: {offset}')
                # look ahead
                offset_2 = offset+1
                ahead_found = False 
                for i in range(offset_2, len(messages)):
                    m_ahead = messages[i]
                    if m_ahead.is_leave:
                        # probably should be default behavior to match the exact mangled name..
                        if functype == "readUtf8FromUtf16":
                            if m_ahead.binderfunc == m.binderfunc:
                                offset = i + 1
                                ahead_found = True
                                self.log(f'found matching leave message moving offset to {offset}')
                                break
                        else:
                            f_ahead = mangled2functype(m_ahead.binderfunc)
                            if f_ahead == functype:
                                offset = i + 1
                                ahead_found = True
                                self.log(f'found matching leave message moving offset to {offset}')
                                break
                if not ahead_found:
                    self.log(f'no end function found exiting')
                    # prune everything
                    offset = len(messages)
            else:
                if(m.is_leave and not (m.is_readParceableArray() or m.is_readParceableArrayEnd() or m.is_setDataPosition())):
                    offset+= 1
                else:
                    self.log(f'adding message {m}, no pruning')
                    messages_pruned.append(m)
                    offset += 1
        return messages_pruned

    def handle_readParceble(self, messages: list[RecvRefineData]):
        #TODO: currently no support for nested parceableArrays
        messages_adapted = []
        offset = 0
        self.log(f'handling readParceble messages from {len(messages)} messages')
        while offset < len(messages):
            m = messages[offset]
            print(m)
            if m.is_readParceableArray() or m.is_unsafeReadTypedVector():
                # look for end 
                parceble_deser = []
                offset += 1
                setDataPosition_found = False
                while offset < len(messages):
                    m2 = messages[offset]
                    if m2.is_readParceableArrayEnd() or m2.is_unsafeReadTypedVectorEnd():
                       break
                    if m2.is_setDataPosition():
                        setDataPosition_found = True
                    if not setDataPosition_found:
                        parceble_deser.append(m2)
                    offset += 1
                if len(parceble_deser) > 0:
                    if parceble_deser[0].is_readInt32():
                        # change entry to int32parceablearraysize
                        parceble_deser[0].is_parcebleArraySize = True
                    else:
                        # insert int32parceablearraysize entry
                        new_entry = RecvRefineData({"type": "Binderfunc", "name": 
                                                    "AParcel_readInt32", 
                                                    "pid": m.pid, 
                                                    "call_counter": -1})
                        new_entry.is_parcebleArraySize = True
                        parceble_deser = [new_entry] + parceble_deser
                else:
                    # insert int32parceablearraysize entry
                    new_entry = RecvRefineData({"type": "Binderfunc", "name": 
                                                "AParcel_readInt32", 
                                                "pid": m.pid, 
                                                "call_counter": -1})
                    new_entry.is_parcebleArraySize = True
                    parceble_deser = [new_entry] 
                for m3 in parceble_deser:
                    m3.is_parcebleArrayEntry = True
                    messages_adapted.append(m3)
            else:
                if not m.is_setDataPosition():
                    messages_adapted.append(m)
            offset += 1 
        return messages_adapted

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
        adb.push_privileged(os.path.join(BASE_DIR, "..", "tools", "example_apk", "test.apk"),
                            "/data/local/tmp",
                            device_id=self.device_id)


    def upload_seeds(self, remote_seed_dir, create_phase1_dir=False):
        if adb.path_exists(remote_seed_dir, device_id=self.device_id):
            adb.execute_privileged_command(
                f"rm -rf {remote_seed_dir}", device_id=self.device_id
            )
        else:
            adb.execute_privileged_command(
                f"mkdir -p {remote_seed_dir}", device_id=self.device_id
            )
        # create a local phase_1 directory
        if create_phase1_dir:
            phase1_local_dir = os.path.join(
                self.seed_path, os.path.basename(remote_seed_dir)
            )
            run_cmd(f"mkdir -p {phase1_local_dir}")
            run_cmd(f"mkdir -p {phase1_local_dir}")
            for cmd_id, seeds in self.data_seeds.items():
                cmd_dir = os.path.join(phase1_local_dir, str(cmd_id))
                run_cmd(f"mkdir -p {cmd_dir}")
                for seed in seeds:
                    run_cmd(f"cp {seed.file_path} {cmd_dir}")
                    remote_seed = os.path.join(
                        remote_seed_dir,
                        str(cmd_id),
                        os.path.basename(seed.file_path),
                    )
                    seed.remote_path = remote_seed
            adb.push_privileged(
                phase1_local_dir,
                REPLAY_PATH,
                device_id=self.device_id,
                is_directory=True,
            )
        else:
            if len(self.data_seeds) == 0 and len(self.ordered_seeds) == 0:
                return
            for cmd_id, seeds in self.data_seeds.items():
                for seed in seeds:
                    remote_seed = os.path.join(
                        remote_seed_dir, os.path.basename(seed.file_path)
                    )
                    seed.remote_path = remote_seed
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

    def setup_replay(self, remote_seed_dir, create_phase1_dir=False):
        # setup refine folder on the device
        self.log("setting up device")
        self.setup_device()
        # upload the seeds for replay
        self.log("uploading seeds")
        self.upload_seeds(remote_seed_dir, create_phase1_dir=create_phase1_dir)
        # set deserialization functions
        deser_used = database.get_used_deser_mangled(
            self.binder_db, self.service.db_id
        )
        self.deser_used = deser_used
        self.log(f"used deserializers: {self.deser_used}")

    def pull_pid(self):
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

    def do_replay(self, seed):
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
            f"rm {PID_PATH}", device_id=self.device_id, timeout=30
        )
        adb.execute_privileged_command(
            f"rm {PID_ACK_PATH}", device_id=self.device_id, timeout=30
        )

    def parse_seeds(self):
        # parse the seeds (deserialize fuzzparcel)
        seeds = defaultdict(list)
        data_dir = os.path.join(self.seed_path, "data")
        if not os.path.exists(data_dir):
            self.log(f"seed output directory: {data_dir} does not exist")
            return
        if len(os.listdir(data_dir)) == 0:
            self.log(f"no seeds in the data directory {data_dir}")
            return
        for root, dirs, files in os.walk(data_dir):
            for seed_file in files:
                if seed_file.startswith("seed-"):
                    continue
                seed_file = os.path.join(root, seed_file)
                if os.path.isdir(seed_file):
                    continue
                seed = fuzzparcel.deserialize_parcel(open(seed_file, "rb").read())
                if seed is None:
                    continue
                seed.file_path = seed_file
                seeds[seed.code].append(seed)
        self.data_seeds = seeds
        # get seeds in order
        raw_list = []
        for seed_file in os.listdir(data_dir):
            seed_filename = seed_file
            if seed_file.startswith("seed-"):
                continue
            seed_file = os.path.join(data_dir, seed_file)
            if os.path.isdir(seed_file):
                continue
            seed = fuzzparcel.deserialize_parcel(open(seed_file, "rb").read())
            if seed is None:
                continue 
            iteration, sha1, timestamp = seed_filename.split("-")
            timestamp = int(timestamp)
            iteration = int(iteration)
            raw_list.append((iteration, timestamp, seed_file))
        ordered_data_seeds = [d[2] for d in sorted(raw_list, key=lambda x: (x[1], x[0]))]
        for s in ordered_data_seeds:
            self.ordered_seeds.append(SeedBare(os.path.join(data_dir, s)))
        # insert the unrefined seeds into the phase1_seeds database table
        # TODO

    ############################################################################
    # Replay Single Seed 
    ############################################################################

    def single(self):
        # parse the seeds, merge seeds with same command id
        self.log("replaying a single seed against service")
        self.setup_replay(os.path.join(REPLAY_PATH, "data"))
        seed  = SeedBare(self.seed_path)
        seed.remote_path = os.path.join(REPLAY_PATH, os.path.basename(self.seed_path))
        adb.push_privileged(seed.file_path, seed.remote_path, device_id=self.device_id)
        crashed = self.single_replay_seed(seed)
        if crashed:
            self.log(f"single replay Service CRASHED!")
        self.log(f"finished replay")

    def single_replay_seed(self, seed):
        try:
            if not self.service.check_service():
                # wait for service to come back up
                self.log("waiting for service to come back")
                self.service.wait_for_service()
            caller = threading.Thread(target=self.do_replay, args=[seed])
            caller.start()
            caller.join()
            return not adb.is_pid_running(self.service.pid, self.device_id)
        except adb.ADBDeviceOffline as e:
            self.log(f"ADBDeviceOffline during replay_seed: {str(e)}")
            adb.reboot(device_id=self.device_id)
            adb.wait_for_device(self.device_id)
        except adb.ADBDeviceNotFound as e:
            self.log(f"ADBeviceNotFound during replay_seed: {str(e)}")
            adb.wait_for_device(self.device_id)
        except adb.ADBTimeoutException as e:
            self.log(f"TimeoutError while witing for service {str(e)}")
            adb.reboot(device_id=self.device_id)
            adb.wait_for_device(self.device_id)
        return False
        #TODO: add timeout and reboot device

    ############################################################################
    # Seed Refinement
    ############################################################################

    def backup_phase1_seeds(self):
        phase_1_backup_path = os.path.join(self.seed_path, PHASE_1_BACKUP_DATA)
        run_cmd(f"mkdir -p {phase_1_backup_path}")
        run_cmd(f"cp -r {self.seed_path}/data/* {phase_1_backup_path}/")

    def refine(self):
        # parse the seeds, merge seeds with same command id
        self.log("parsing seeds")
        self.parse_seeds()
        if self.data_seeds is None:
            self.log(f"no phase 1 seeds, returning")
            return
        if len(self.data_seeds) == 0:
            self.log(f"length of seeds is 0, nothing to do: {self.seed_path}")
            return
        self.backup_phase1_seeds()
        self.setup_replay(PHASE1_SEED_PATH, create_phase1_dir=True)
        for cmd_id, seeds in self.data_seeds.items():
            for seed in seeds:
                for _ in range(0, SEED_REPLAYS):
                    self.refine_replay_seed(seed)
        self.log(f"finished replay, starting refinement")
        self.refine_seeds()

    def on_message_refine(self, message, data):
        self.log(f"on_message: {message}")
        if message["type"] == "send":
            payload = json.loads(message["payload"])
            payload_type = payload["type"]
            if payload_type == "setup_done":
                self.frida_ready = True
            elif payload["type"] == "assocClass":
                self.log(f"assocClass message, interface name: {payload['name']}")
                self.interface_names.append(payload["name"])
            elif payload["type"] == "Binderfunc" \
                    or payload["type"] == "onTransact_end" \
                    or payload["type"] == "Binderfunc_exit":
                parsed_message = RecvRefineData(payload)
                self.replay_messages.append(parsed_message)
            elif payload["type"] == "readParcelableArray" or \
                payload["type"] == "readParcelableArray_exit":
                parsed_message = RecvRefineData(payload)
                self.replay_messages.append(parsed_message) 
            elif payload["type"] == "AParcel_setDataPosition":
                parsed_message = RecvRefineData(payload)
                self.replay_messages.append(parsed_message) 
            else:
                self.log(f"unknown message {payload}")

    def refine_replay_seed(self, seed):
        try:
            if not self.service.check_service():
                # wait for service to come back up
                self.log("waiting for service to come back")
                self.service.wait_for_service()
            if not self.frida_injected():
                if not adb.path_exists(REPLAY_PATH, device_id=self.device_id):
                    self.setup_replay(PHASE1_SEED_PATH, create_phase1_dir=True)
                # inject frida script
                self.log("loading frida script")
                self.setup_script(self.refine_script, self.on_message_refine)
                self.script.load()
                while not self.frida_ready:
                    self.log("waiting for frida script to come up...")
                    time.sleep(1)
                # set onTransact binary
                self.script.exports_sync.setonstransact(
                    self.service.onTransact.entry_addr,
                    os.path.basename(self.service.onTransact.bin),
                    self.service.onTransact.BBinder_path,
                )
                # hook the relevant used binder functions
                for binder_func in self.deser_used:
                    self.log(f"hooking {binder_func}")
                    self.script.exports_sync.addtohook(binder_func)
                # start instrumentation
                self.script.exports_sync.instrument()
            caller = threading.Thread(target=self.do_replay, args=[seed])
            caller.start()
            caller.join()
        except adb.ADBDeviceOffline as e:
            self.log(f"ADBDeviceOffline during replay_seed: {str(e)}")
            if IS_EMULATOR:
                adb.reboot(device_id=self.device_id)
            adb.wait_for_device(self.device_id)
        except adb.ADBDeviceNotFound as e:
            self.log(f"ADBeviceNotFound during replay_seed: {str(e)}")
            if IS_EMULATOR:
                adb.reboot(device_id=self.device_id)
            adb.wait_for_device(self.device_id)
        except adb.ADBTimeoutException as e:
            self.log(f"TimeoutError while witing for service {str(e)}")
            adb.reboot(device_id=self.device_id)
            adb.wait_for_device(self.device_id)
        except adb.DeviceTimeoutException as e:
            self.log(f"TimeoutError while waiting for service {str(e)}")
            adb.reboot(device_id=self.device_id)
            adb.wait_for_device(self.device_id)

        #TODO: add timeout and reboot device

    def dump_interface(
        self, out_folder: str, interface: Interface, prefix="ref"
    ):
        fuzzparcels = interface.to_fuzzparcels()
        for fuzzparcel in fuzzparcels:
            fuzzparcel_bytes = fuzzparcel.to_bytes()
            filepath = os.path.join(
                out_folder, f"{prefix}-{utils.sha1sum(fuzzparcel_bytes)}"
            )
            open(filepath, "wb+").write(fuzzparcel_bytes)

    def dump_known(
            self, code, parcel: fuzzparcel.FuzzParcel, prefix="ref"
    ):
        if code == 0x5f434d44:
            ref_parcel = fuzzparcel.FuzzParcel(code, 6)
            ref_parcel.entries.append(fuzzparcel.ParcelEntry(fuzzparcel.ParcelType.FILEDESCRIPTOR, 8, b"A"*8))
            ref_parcel.entries.append(fuzzparcel.ParcelEntry(fuzzparcel.ParcelType.FILEDESCRIPTOR, 8, b"A"*8))
            ref_parcel.entries.append(fuzzparcel.ParcelEntry(fuzzparcel.ParcelType.FILEDESCRIPTOR, 8, b"A"*8))
            ref_parcel.entries.append(fuzzparcel.ArrayVarLengthEntry(
                fuzzparcel.ParcelType.STRING16VECTOR, [b"asdf", b"asdf", b"asdf"]
            ).to_parcel_entry())
            ref_parcel.entries.append(fuzzparcel.StrongBinderEntry(b"android.IShellCallback", b"asdf").to_parcel_entry())
            ref_parcel.entries.append(fuzzparcel.StrongBinderEntry(b"android.IResultReceiver", b"asdf").to_parcel_entry())
            out_path = os.path.join(self.seed_path, PHASE_2_SEED_DIRNAME, str(code))
            run_cmd(f'mkdir -p {out_path}')
            ref_parcel_bytes = ref_parcel.to_bytes()
            filepath = os.path.join(
                out_path, f"{prefix}-{utils.sha1sum(ref_parcel_bytes)}"
            )
            open(filepath, "wb+").write(ref_parcel_bytes) 

    def refine_seeds(self):
        # associate messages with replayed seeds
        pid2message = defaultdict(list)
        pid2message_2 = defaultdict(list)
        for msg in self.replay_messages:
            pid2message[msg.pid].append(msg)
        self.log(f'pid2message one: {len(pid2message)}')
        for pid, messages in pid2message.items():
            messages = list(sorted(messages, key=lambda x: x.call_counter))
            if messages[-1].typ == "onTransact_end":
                messages = messages[:-1]
            # remove extra calls (like readInt32Vector may call readInt32)
            messages = self.prune_extra_calls(messages)
            pid2message_2[pid] = messages
        self.log(f'pid2message after pruning: {len(pid2message_2)}')
        for pid, messages in pid2message_2.items():
            # readParcebla messages read an int as size, mark this!
            messages = self.handle_readParceble(messages)
            pid2message_2[pid] = messages
        cmd2data = defaultdict(list)
        for cmd_id, seeds in self.data_seeds.items():
            seed2data = {}
            for seed in seeds:
                self.log(f'generating interface defintion for {seed}')
                for pid in self.seed2pid[seed]:
                    seed2data[seed] = generate_interface_definition(
                        seed, pid2message_2[pid], 
                        self.interface_names
                    )
            cmd2data[cmd_id] = seed2data
        cmd_id2reference = {}
        for cmd_id, data in cmd2data.items():
            maxdeser = -1
            maxuniquedeser = -1
            reference_interface = None
            for seed, interface in data.items():
                # TODO: we don't take into account differing code paths in onTransact
                if interface.size() > maxdeser and len(set([a[0] for a in interface.known_deserializers if a is not None])) > maxuniquedeser:
                    if interface.size() > MAX_ENTRIES:
                        interface.crop()
                    maxdeser = interface.size()
                    maxuniquedeser = len(set([a[0] for a in interface.known_deserializers if a is not None]))
                    reference_interface = interface
            self.log(f"{cmd_id}: {reference_interface}")
            if reference_interface is not None:
                cmd_id2reference[cmd_id] = reference_interface
        phase_2_seed_dir = os.path.join(self.seed_path, PHASE_2_SEED_DIRNAME)
        if not os.path.exists(phase_2_seed_dir):
            run_cmd(f"mkdir -p {phase_2_seed_dir}")
        for cmd_id, reference_interface in cmd_id2reference.items():
            # add reference interface to database
            insert_interface_into_db(
                self.binder_db, self.service, reference_interface
            )
            cmd_folder = os.path.join(phase_2_seed_dir, str(cmd_id))
            run_cmd(f"mkdir -p {cmd_folder}")
            out_path = os.path.join(cmd_folder, f"ref-")
            # create a seed based on the reference interface
            self.dump_interface(cmd_folder, reference_interface)
        """
        # 
        # go through crashes, parse the command id, if the command id is a known 
        # command id (https://cs.android.com/android/platform/superproject/main/+/main:frameworks/native/libs/binder/include/binder/IBinder.h)
        # if it is we can generate a correct reference seed
        crashes = []
        for f in os.listdir(self.seed_path):
            p = os.path.join(self.seed_path, f)
            if f.startswith("crash-") and not os.path.isdir(p):
                crashes.append((f, p))
        for crash, crash_path in crashes:
            parcel_deser = fuzzparcel.deserialize_parcel(open(crash_path, 'rb').read())
            if parcel_deser.code in BINDER_KNOWN_CMDS:
                self.log(f'known command id in crashing adding ref seed: {hex(parcel_deser.code)}')
                self.dump_known(parcel_deser.code, parcel_deser)
        """

        # TODO: enhance existing seeds, "casting" them to the reference interface

    ############################################################################
    # Drcov
    ############################################################################

    def drcov(self):
        # replay seeds and extract drcov (replay all seeds in data directory)
        self.parse_seeds()
        self.setup_replay(DATA_SEED_PATH)
        data_dir = os.path.join(self.seed_path, "data")
        if not os.path.exists(data_dir):
            self.log(f"{data_dir} does not exist!")
        for seed in self.ordered_seeds:
            for _ in range(0, SEED_REPLAYS):
                self.drcov_replay_seed(seed)
                self.extract_bbs(seed)
                self.replay_messages = []  # clear messages from pipeline
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

    def drcov_replay_seed(self, seed):
        try:
            if not self.service.check_service():
                # wait for service to come back up
                self.log("waiting for service to come back")
                self.service.wait_for_service()
            if not self.frida_injected():
                # check if replay is still setup
                if not adb.path_exists(REPLAY_PATH, device_id=self.device_id):
                    self.setup_replay(DATA_SEED_PATH)
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
            caller = threading.Thread(target=self.do_replay, args=[seed])
            caller.start()
            caller.join()
        except adb.ADBDeviceNotFound as e:
            self.log(f"ADBeviceNotFound during replay_seed: {str(e)}")
            adb.wait_for_device(self.device_id)
        except adb.ADBTimeoutException as e:
            self.log(f"TimeoutError while witing for service {str(e)}")
            adb.reboot(device_id=self.device_id)
            adb.wait_for_device(self.device_id)
        except adb.DeviceTimeoutException as e:
            self.log(f"TimeoutError while waiting for service {str(e)}")
            adb.reboot(device_id=self.device_id)
            adb.wait_for_device(self.device_id)

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
        self.log(f"filtering messages caller pids: {[m.pid for m in self.replay_messages]}, own caller pid: {self.seed2pid[seed]}")
        messages = [
            m for m in self.replay_messages if m.pid in self.seed2pid[seed]
        ]
        block_sz = 8
        seed_bbs = set([])
        self.log(f"extracting bbs for {len(messages)}")
        for m in messages:
            for i in range(0, len(m.data), block_sz):
                seed_bbs.add(m.data[i : i + block_sz])
                self.all_bbs.append(m.data[i : i + block_sz])
        self.seed2bbs[seed] = seed_bbs

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
        "action",
        type=str,
        choices=["refine", "drcov", "single"],
        help="refine: replay seeds and extract exact interface, \
            extract drcov coverage from seeds \
                single: replay a single seed",
    )
    parser.add_argument(
        "-s",
        "--service_name",
        type=str,
        required=False,
        help="name of native service",
    )
    parser.add_argument(
        "-d", "--device", type=str, required=False, help="device to test"
    )
    parser.add_argument(
        "-f",
        "--file_path",
        type=str,
        required=True,
        help="specify path to fuzzing run output directory",
    )
    parser.add_argument(
        "-r",
        "--random_seeds",
        default=False,
        required=False,
        help="if set will generate random seeds into the fuzz folder"
    )
    args = parser.parse_args()

    if args.device is not None and args.service_name is not None:
        device_id  = args.device
        service_name = args.service_name
    else:
        device_id, service_name, _, _ = parse_path(args.file_path)
        if args.device is not None:
            device_id = args.device
        if args.service_name is not None:
            service_name = args.service_name

    
    if device_id not in adb.get_device_ids():
        if IS_EMULATOR:
            print(f'[ORC] emulator starting up')
            emulator.full_reset(args.device) 
        else:
            print(f'{RED} device {args.device} not connected')
            exit(-1)

    ############################################################################
    # sanity check before starting
    ############################################################################

    if args.action == "drcov" or args.action == "refine": 
        if not os.path.exists(os.path.join(args.file_path, "data")):
            print(
                f"{RED}{args.file_path}/data does not exist, \
                    cannot proceed without seeds..{NC}"
            )
            exit(-1)

    ############################################################################
    # select device to fuzz on
    ############################################################################

    devices = frida.enumerate_devices()
    possible_devices = [d for d in devices if d.type == "usb"]
    possible_devices = [
        d for d in possible_devices if not "ios" in d.name.lower()
    ]
    device = None
    if device_id is not None:
        if device_id not in [d.id for d in possible_devices]:
            print(f"{RED}[-] device not connected!{NC}")
            print(
                f"connected devices: ",
                ",".join([d.id for d in possible_devices]),
            )
        else:
            device = [d for d in possible_devices if d.id == device_id][0]
    if device is None:
        exit(-1)

    ############################################################################
    # reset the device
    ############################################################################

    print("[REF] resetting device, killing service and waiting for device")
    adb.reset_service(service_name, device.id)
    print("[REF] finished reset, continuing")

    ############################################################################
    # retrieve target service info obtained from pre-processing
    ############################################################################

    binder_db = database.open_db()
    if META_TARGET is None:
        svc = database.get_service(binder_db, service_name, device.id)
    else:
        svc = database.get_service(binder_db, service_name, META_TARGET, 
                                            real_device_id=device.id)
    if svc is None or svc.onTransact is None:
        print(
            f"{RED}Service not in db, run interface onTransact enumeration first!{NC}"
        )
        exit(-1)

    ############################################################################
    # start orchestrator
    ############################################################################

    rep = Replayer(service_name, device, svc, args.file_path, binder_db, meta_device_id=META_TARGET)
    if args.action == "refine":
        rep.action = "REF"
        rep.refine()
    elif args.action == "drcov":
        rep.action = "DRCOV"
        rep.drcov()
    elif args.action == "single":
        rep.action = "SINGLE"
        rep.single()
    else:
        print(f"Unknown command..")
