import threading
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

BASE_DIR: str = os.path.dirname(__file__)
sys.path.append(os.path.join(BASE_DIR, ".."))

from config import (
    LIBRARY_BLOCKLIST,
    TARGET_DIR,
    SHMEM,
    FRIDA_MAP_SIZE,
    TMPFS,
    FRIDA_SERVER_DIR,
    PAIN,
    FRIDA_VERSION,
    NC,
    RED,
    PURPLE,
    CUSTOM_DUMPSYS_PATH,
    NEED_CUSTOM_DUMPSYS,
    META_TARGET,
    IS_EMULATOR,
    FUZZ_REBOOTS_TRACKER,
    FUZZ_TIMEOUTS_TRACKER,
    FUZZ_START_TIME,
    FUZZ_END_TIME,
    FANS_NOVARMAP_FILE
)
import service.vanilla as vanilla
import data.database as database
import utils.utils as utils
import emulator.emulator as emulator
import adb


frida_script = os.path.join(BASE_DIR, "..", "fuzz", "fridajs", "fuzz.js")
device_path = os.path.join(BASE_DIR, "..", "device")

if len(logging.root.handlers) == 0:
    logging.basicConfig(
        filename=os.path.join(BASE_DIR, "log", "fans-orchestrate.log"),
        encoding="utf-8",
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(filename)s.%(funcName)s %(message)s",
        force=True,
    )


FRIDA_PATH = "/data/local/tmp/frida"
FUZZER_PATH = "/data/local/tmp/fans-cov"
PID_PATH = os.path.join(FUZZER_PATH, ".pid")
PID_ACK_PATH = os.path.join(FUZZER_PATH, ".pid_ack")
FUZZ_DATA_PATH = os.path.join(FUZZER_PATH, "data")
FUZZ_LOG_PATH = os.path.join(FUZZER_PATH, "logs")
DESERIAL_USED_PATH = os.path.join(FUZZER_PATH, "deserializers_used.txt")
LIBFUZZ_LOG = os.path.join(FUZZER_PATH, "log.txt")
DEBUG_LOG = os.path.join(FUZZER_PATH, "debug.txt")
SEED_SHA1S = os.path.join(FUZZER_PATH, "seed_sha1s.txt")

PID_MAX_ITERS = 120

TIMEOUT = 10

class HookNotHit(Exception):
    pass

class CodeRange:
    def __init__(self, start, end) -> None:
        self.start = start
        self.end = end


class FuzzOrchestrator:
    def __init__(
        self,
        service_name,
        device,
        svc_obj,
        binder_db,
        do_pid_filter=False,
        fuzz_debug=False,
        torun=0x1000000000000,
        meta_device_id=None,
        novarmap=False
    ) -> None:
        self.service = vanilla.Vanilla.fromService(svc_obj)
        self.service.adb_data()
        self.device = device
        self.device_id = self.device.id
        if meta_device_id is None:
            self.meta_device_id = self.device_id
        else:
            self.meta_device_id = meta_device_id
        self.binder_db = binder_db
        self.process = None
        self.script = None
        self.frida_ready = False
        self.frida_injected = False
        self.fuzzer_setup = False
        self.fuzzer_pid = None
        self.do_pid_filter = do_pid_filter
        self.fuzz_debug = fuzz_debug
        self.time_torun = torun
        self.iteration = 0
        self.time_running = 0
        self.nr_service_crashed = 0
        self.nr_device_borked = 0
        self.start_time = None
        self.fuzz_orchestrator_log = None
        self.ranges_to_instrument = []
        self.line_printed = 0
        target_interface = self.service.onTransact.interface
        if novarmap:
            self.novarmap = novarmap
            self.fuzzer_name = "native_service_fuzzer_coverage_novarmap"
        else:
            self.novarmap = novarmap
            self.fuzzer_name = "native_service_fuzzer_coverage"
        if target_interface is None:
            print("Error target service interface not found..")
            exit(-1)
        top_level_interface = target_interface.split(".")[-1]
        self.target_interface = top_level_interface
        logging.info(f'target interface: {self.target_interface}') 
        if not self.is_db_uptodate():
            print(
                f"[ERROR][ORC] hash of onTransact binary does not match with the one in database, please rerun interface enumeration"
            )
            print(
                f"python3 instrument/interface.py -s {service_name} -t onTransact --device {self.device_id} -c vanilla --ignore_cache"
            )
            exit(1)
        if IS_EMULATOR:
            self.renew_frida_device()

    def orchestrate_log(self, line):
        line = line.strip("\n")
        print(f"[ORC][{self.device_id}] {line}")
        if self.fuzz_orchestrator_log is not None:
            open(self.fuzz_orchestrator_log, "a+").write(
                f'{datetime.now().strftime("%d.%m.%Y_%H:%M:%S")} {self.device_id}-- {line}\n'
            )

    def is_db_uptodate(self):
        local = os.path.join(
            "/tmp", os.path.basename(self.service.onTransact.bin)
        )
        adb.pull_privileged(
            self.service.onTransact.bin, local, device_id=self.device_id
        )
        md5 = utils.get_md5(local)
        return md5 == self.service.onTransact.md5

    def setup_script(self, script_path, on_message_func):
        self.setup_frida()
        while 1:
            try:
                self.process = self.device.attach(self.service.pid)
                self.script = self.process.create_script(
                    open(script_path).read()
                )
                self.script.on("message", on_message_func)
                self.frida_injected = True
                break
            except frida.NotSupportedError:
                self.orchestrate_log(
                    "service is in fucked state.. killing service"
                )
                adb.kill_service(
                    self.service.service_name, device_id=self.device_id,
                    timeout=5
                )
                adb.kill_frida(device_id=self.device_id, timeout=5)
                time.sleep(10)

    def on_message(self, message, data):
        logging.debug(f"message received: {message}")
        # print(f"message received: {message}")
        if message["type"] == "send":
            payload = json.loads(message["payload"])
            payload_type = payload["type"]
            if payload_type == "setup_done":
                self.frida_ready = True
            # else:
            #    print("unkwon message: ", payload_type)
        # else:
        #    print("unknown message: ", message)

    def print_fuzzer_cmd(self):
        print("run fuzzer with: ")
        print(self.fuzzer_cmd())

    def fuzz_sysconfig(self):
        if self.device_id == "RZCX312P76A":
            return
        adb.execute_privileged_command("setenforce 0", device_id=self.device_id)
        adb.execute_privileged_command(
            "cd /sys/devices/system/cpu && echo performance | tee cpu*/cpufreq/scaling_governor",
            device_id=self.device_id,
        )
        return

    def pull_pid(self, timeout=10):
        elapsed = 0
        while True:
            out, _ = adb.execute_privileged_command(
                f"cat {PID_PATH}", device_id=self.device_id
            )
            try:
                out = int(out.decode())
                return out
            except ValueError:
                if elapsed > timeout:
                    return None
                logging.warning(f"pid not pulled, waiting...")
                time.sleep(0.1)
                elapsed += 0.1
                continue

    def fuzzer_running(self):
        if self.fuzzer_pid is None:
            return False
        return adb.is_pid_running(
            self.fuzzer_pid, self.device_id, 
            bin_name=self.fuzzer_name
        )

    def onTransact_hook_hit(self):
        # very dumb check to make sure we're actually hitting the onTransact check
        out, err = adb.execute_privileged_command(f'logcat -d -s fuzzer', 
                                                  device_id=self.device_id)
        return b"start onTransact hook" in out

    def check_device(self):
        status = adb.check_device(device_id=self.device_id)
        if status == "OK":
            return True
        return False

    def check_service(self):
        if self.service.pid is None:
            return False
        return adb.is_pid_running(self.service.pid, self.device_id)

    def print_status(self, time_running, nr_service_crashed, nr_device_borked, full=False):
        toprint = ""
        if full:
            toprint = f"======[BINDERFUZZER STATUS][{time_running}]=======\n"
            toprint += f"[OVERALL] service pid: {self.service.pid}, #service crashed: {nr_service_crashed}, #device borked: {nr_device_borked}\n"
            toprint += f"[OVERALL] output: {self.fuzz_out_dir}\n"
        log_file = os.path.join(self.fuzz_out_dir, "log.txt")
        if os.path.exists(log_file):
            stats = open(log_file).read().split("\n")
            # Read the file starting from the specified line
            for line in stats[self.line_printed:]:
                if line == "":
                    continue
                toprint += f"[LIBFUZZ] {line}\n"
                self.line_printed += 1
        else:
            toprint += f"[NO FUZZER LOGS]\n"
            self.line_printed = 0
        toprint += "=========================="
        print(toprint)

    def fuzz_clean(self):
        adb.execute_privileged_command(
            f"rm -rf {FUZZER_PATH}", device_id=self.device_id
        )

    def setup_outdir(self):
        out_folder = datetime.now().strftime("fans_%d_%m_%Y_%H%M%S.%f")
        fuzz_out_path = os.path.join(
            TARGET_DIR,
            self.meta_device_id,
            self.service.service_name,
            "fuzz_out",
            out_folder,
        )
        if not os.path.exists(fuzz_out_path):
            os.system(f"mkdir -p {fuzz_out_path}")
        fuzz_out_logs = os.path.join(fuzz_out_path, "logs")
        os.system(f"mkdir -p {fuzz_out_logs}")
        self.fuzz_out_dir = fuzz_out_path
        self.start_time_file = os.path.join(self.fuzz_out_dir, FUZZ_START_TIME)
        self.end_time_file = os.path.join(self.fuzz_out_dir, FUZZ_END_TIME)
        self.reboots_file = os.path.join(self.fuzz_out_dir, FUZZ_REBOOTS_TRACKER)
        if not os.path.exists(self.reboots_file):
            os.system(f'touch {self.reboots_file}')
        self.timeouts_file = os.path.join(self.fuzz_out_dir, FUZZ_TIMEOUTS_TRACKER)
        if not os.path.exists(self.timeouts_file):
            os.system(f'touch {self.timeouts_file}')
        if self.novarmap:
            varmap_file = os.path.join(self.fuzz_out_dir, FANS_NOVARMAP_FILE)
            os.system(f'touch {varmap_file}')
        self.fuzz_out_logs = fuzz_out_logs
        self.fuzz_orchestrator_log = os.path.join(
            fuzz_out_path, "fuzzer_log.txt"
        )

    def store_reboot(self, description):
        open(self.reboots_file, 'a').write(f'{int(time.time())} {description}\n')

    def store_timeout(self):
        open(self.timeouts_file, 'a').write(f'{int(time.time())}\n')

    def store_start_time(self):
        open(self.start_time_file, 'w+').write(f'{int(time.time())}')

    def store_end_time(self):
        open(self.end_time_file, 'w+').write(f'{int(time.time())}')

    def pull_logcat(self):
        logging.debug(f"[ORC] pulling logcat crashlog...")
        log = adb.logcat_crashlog(device_id=self.device_id)
        new_log = os.path.join(
            self.fuzz_out_logs,
            f"{int(time.time())}_crashlog.txt",
        )
        open(new_log, "w+").write(log)

    def pull_fuzzdata(self):
        logging.debug(f"[ORC] downloading fuzzing data")
        out, _ = adb.execute_privileged_command(
            f"ls {FUZZER_PATH}", device_id=self.device_id
        )
        out = out.decode().split("\n")
        for f in out:
            if f.startswith("crash-"):
                adb.pull_privileged(
                    f"{FUZZER_PATH}/{f}",
                    self.fuzz_out_dir,
                    device_id=self.device_id,
                )
        adb.pull_privileged(
            FUZZ_DATA_PATH,
            self.fuzz_out_dir,
            device_id=self.device_id,
            is_directory=True,
        )
        adb.pull_privileged(
            f"{FUZZ_DATA_PATH}/deserializers_used.txt",
            self.fuzz_out_dir,
            device_id=self.device_id,
        )
        adb.pull_privileged(
            LIBFUZZ_LOG, self.fuzz_out_dir, device_id=self.device_id
        )
        adb.pull_privileged(
            LIBFUZZ_LOG,
            os.path.join(
                self.fuzz_out_logs,
                f"{self.nr_device_borked+self.nr_service_crashed}_log.txt",
            ),
            device_id=self.device_id,
        )
        adb.pull_privileged(
            SEED_SHA1S,
            self.fuzz_out_dir,
            device_id=self.device_id,
        )
        if self.fuzz_debug:
            adb.pull_privileged(
                DEBUG_LOG, self.fuzz_out_dir, device_id=self.device_id
            )

    def wait_for_device(self):
        if IS_EMULATOR:
            self.orchestrate_log('resetting emulator in wait_for_device!')
            emulator.reset(self.device_id)
            return
        # TODO: maybe something smarter:
        logging.debug(f"waiting for device to recover sleeping for 5")
        while 1:
            device_offline = False
            try:
                device_offline = adb.is_device_offline(self.device_id)
            except adb.ADBDeviceNotFound:
                pass
            if device_offline:
                self.orchestrate_log('device is offline..!')
            if self.device_id in adb.get_device_ids():
                try:
                    # add function to health check service
                    if adb.check_device(device_id=self.device_id) == "OK":
                        time.sleep(5)
                        return
                except adb.ADBDeviceNotFound:
                    self.orchestrate_log(
                        f"ADB devicenodfound while trying to check_device, waiting more..."
                    )
                    pass
            self.orchestrate_log(f"waiting for device to reboot...")
            time.sleep(5)
            if time.time() - self.start_time > self.time_torun:
                # while waiting for the device we've run out of time, exit now
                self.orchestrate_log(
                    f"hit waiting time while waiting for device, exiting"
                )
                return
            # input("[ORC] device is completely fucked, please restart yourself.. :) (press Enter once done)")

    def renew_frida_device(self):
        devices = frida.enumerate_devices()
        possible_devices = [d for d in devices if d.type == "usb"]
        possible_devices = [
            d for d in possible_devices if not "ios" in d.name.lower()
        ]
        self.orchestrate_log(f"frida devices: {possible_devices}")
        possible_devices = [d for d in possible_devices if d.id == args.device]
        if len(possible_devices) == 0:
            logging.error(f"frida device not found, completely fucked...")
            self.orchestrate_log(f"frida device not found...")
        elif len(possible_devices) == 1:
            device = possible_devices[0]
            self.device = device
            logging.warning(f"frida device found and renewed!")
            self.orchestrate_log(f"[ORC] frida device found and renewed!")
        else:
            logging.error(f"frida device not found, completely fucked...")
            self.orchestrate_log(f"[ORC] frida device not found...")
            exit(-1)

    def setup_frida(self):
        # setup fuzzing shared memory file (comes here because the frida script depends on it...)
        self.setup_shm_file(TMPFS, SHMEM, FRIDA_MAP_SIZE)
        arch = self.service.arch
        if arch == "aarch64":
            frida_bin = utils.get_frida_bin(
                "arm64", FRIDA_VERSION, FRIDA_SERVER_DIR
            )
        elif arch == "arm8l":
            frida_bin = utils.get_frida_bin(
                "arm", FRIDA_VERSION, FRIDA_SERVER_DIR
            )
        elif arch == "x86_64":
            frida_bin = utils.get_frida_bin(
                "x86_64", FRIDA_VERSION, FRIDA_SERVER_DIR
            )
        else:
            logging.error(f"unknown archtecture: {arch}")
            print(f"[*] unknown archtecture: {arch}")
            raise Exception
        if frida_bin is None:
            logging.error(
                f"unable to find {arch}, {FRIDA_VERSION} frida in {FRIDA_SERVER_DIR}"
            )
            print(
                f"[*] unable to find {arch}, {FRIDA_VERSION} frida in {FRIDA_SERVER_DIR}"
            )
            raise Exception
        frida_svr = os.path.join(FRIDA_SERVER_DIR, frida_bin)
        if not os.path.exists(frida_svr):
            logging.error(f"Download the necessary frida server: {frida_svr}")
            print(f"{RED}Download the necessary frida server: {frida_svr}{NC}")
            raise Exception
        _, err = adb.execute_privileged_command(
            f"mkdir -p {FRIDA_PATH}", device_id=self.device_id
        )
        if err:
            logging.error(
                f"failed setting up directory: {FRIDA_PATH}, {err}",
                device_id=self.device_id,
            )
            raise Exception
        frida_svr_remote = os.path.join(FRIDA_PATH, os.path.basename(frida_svr))
        if not adb.path_exists(frida_svr_remote, device_id=self.device_id):
            adb.push_privileged(frida_svr, FRIDA_PATH, device_id=self.device_id)
        adb.execute_privileged_command(
            f"chmod +x {frida_svr_remote}", device_id=self.device_id
        )
        logging.info(f"frida setup on {self.device} at {frida_svr_remote}")
        frida_process = os.path.basename(frida_svr)
        out, err = adb.execute_privileged_command(
            f"ps -A | grep frida-server", device_id=self.device_id
        )
        if "frida-server" not in out.decode():
            # start server
            adb.execute_privileged_command(
                f"{frida_svr_remote} &",
                wait_for_termination=False,
                device_id=self.device_id,
            )
        time.sleep(1)
        out, err = adb.execute_privileged_command(
            f"ps -A | grep frida-server", device_id=self.device_id
        )
        if "frida-server" not in out.decode():
            # something went wrong raise an exception
            raise frida.ServerNotRunningError
        adb.wait_for_frida(
            device_id=self.device_id, frida_server_path=frida_svr_remote
        )

    def unload_frida(self):
        self.script.unload()

    def setup_shm_file(self, tmpfs_path, shmem_path, frida_map_size):
        out, err = adb.execute_privileged_command(
            f" mount | grep {tmpfs_path}", device_id=self.device_id
        )
        if not tmpfs_path.encode() in out or not b"type tmpfs" in out:
            out, err = adb.execute_privileged_command(
                f"mkdir -p {tmpfs_path}", device_id=self.device_id
            )
            adb.execute_privileged_command(
                f"mount -t tmpfs tmpfs {tmpfs_path}",
                device_id=self.device_id,
            )
        if adb.path_exists(shmem_path, device_id=self.device_id):
            adb.execute_privileged_command(
                f"rm {shmem_path}", device_id=self.device_id
            )
        adb.execute_privileged_command(
            f"truncate -s {frida_map_size} {shmem_path}", device_id=self.device_id
        )
        adb.execute_privileged_command(
            f"chmod 777 {shmem_path}", device_id=self.device_id
        )
        self.shmem_path = shmem_path
        self.frida_map_size = frida_map_size

    def get_ranges_to_instrument(self):
        # TODO remove standard android libraries
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

    def setup_fuzzer(self, iteration=0):
        # do fuzzer-sysconfig
        self.fuzz_sysconfig()
        # upload fuzzer
        fuzzer_path = os.path.join(BASE_DIR, self.fuzzer_name)
        if not os.path.exists(fuzzer_path):
            print(f"[ORC] fuzzer not compiled! {fuzzer_path}")
            logging.error(f"fuzzer not compiled! {fuzzer_path}")
            raise Exception
        fuzzer_remote_path = os.path.join(
            FUZZER_PATH, os.path.basename(fuzzer_path)
        )
        _, err = adb.execute_privileged_command(
            f"mkdir -p {FUZZER_PATH}", device_id=self.device_id
        )
        if err:
            logging.error(f"failed setting up directory: {FUZZER_PATH}, {err}")
            raise Exception
        if not adb.path_exists(fuzzer_remote_path, device_id=self.device_id):
            adb.push_privileged(
                fuzzer_path, FUZZER_PATH, device_id=self.device_id
            )
            adb.execute_privileged_command(
                f"chmod +x {fuzzer_remote_path}", device_id=self.device_id
            )
        fuzzer_path_debug = os.path.join(BASE_DIR, f'{self.fuzzer_name}_debug') 
        adb.push_privileged(
                fuzzer_path_debug, FUZZER_PATH, device_id=self.device_id
            )
        adb.execute_privileged_command(
                f"chmod +x {FUZZER_PATH}/{self.fuzzer_name}_debug", 
                device_id=self.device_id
            )
        adb.execute_privileged_command(
            f"rm {PID_PATH}", device_id=self.device_id
        )
        adb.execute_privileged_command(
            f"rm {PID_ACK_PATH}", device_id=self.device_id
        )
        if not adb.path_exists(FUZZ_DATA_PATH, device_id=self.device_id):
            adb.execute_privileged_command(
                f"mkdir -p {FUZZ_DATA_PATH}", device_id=self.device_id
            )
        else:
            # clean fuzz output folder
            adb.execute_privileged_command(
                f"rm -rf {FUZZ_DATA_PATH}/*", device_id=self.device_id
            )
            adb.execute_privileged_command(
                f"rm -rf {FUZZER_PATH}/tx_data_dump/*", device_id=self.device_id
            )
        # tx dump folder
        #adb.execute_privileged_command(f'mkdir -p {FUZZER_PATH}/tx_data_dump', device_id=self.device_id)
        # upload FANS specific files
        adb.push_privileged(
            os.path.join(BASE_DIR, 'seed'), FUZZER_PATH, is_directory=True, 
            device_id=self.device_id
            )
        adb.push_privileged(
            os.path.join(BASE_DIR, 'workdir/interface-model-extractor/model'), 
            FUZZER_PATH, is_directory=True, device_id=self.device_id
            )
        adb.push_privileged(
            os.path.join(BASE_DIR, 'fuzzer-engine/fuzzer-coverage'), FUZZER_PATH, 
                         is_directory=True, device_id=self.device_id
            )
        # setup log
        if not adb.path_exists(FUZZ_LOG_PATH, device_id=self.device_id):
            adb.execute_privileged_command(
                f"mkdir -p {FUZZ_LOG_PATH}", device_id=self.device_id
            )
        if iteration > 0:
            # upload existing fuzzing data to resume fuzzing
            if os.path.exists(os.path.join(self.fuzz_out_dir, "data")):
                adb.push_privileged(
                    os.path.join(self.fuzz_out_dir, "data"),
                    FUZZER_PATH,
                    device_id=self.device_id,
                    is_directory=True,
                )
            seed_sha1s = os.path.join(self.fuzz_out_dir, os.path.basename(SEED_SHA1S))
            if os.path.exists(seed_sha1s):
                adb.push_privileged(
                    seed_sha1s,
                    FUZZER_PATH,
                    device_id=self.device_id
                )
        adb.execute_privileged_command(
            f"chmod 777 -R {FUZZER_PATH}", device_id=self.device_id
        )
        if not self.frida_injected:
            print(
                "[!!] ERROR before calling setup_fuzzer inject the frida script!!!!"
            )
            exit(-1)
        self.script.load()
        pid_frida_ready_iters = 0
        while not self.frida_ready:
            if pid_frida_ready_iters > PID_MAX_ITERS:
                logging.error(f"waiting for frida_ready for too long, exiting")
                self.orchestrate_log(
                    f"waiting for frida_ready for too long, exiting"
                )
                exit(0)
            print("[..] waiting for frida to come up")
            time.sleep(1)
            pid_frida_ready_iters += 1
        # set ranges to instrument
        self.script.exports_sync.setonstransact(
            self.service.onTransact.entry_addr,
            os.path.basename(self.service.onTransact.bin),
            self.service.onTransact.BBinder_path,
        )
        self.script.exports_sync.setupshm(self.shmem_path, self.frida_map_size)
        for lib in self.get_ranges_to_instrument():
            code_range = self.service.proc_map.get_vmabyname(lib)
            if code_range is None:
                logging.warning(f"weird, code range not inside: {code_range}")
                continue
            logging.info(
                f"adding code range in range to instrument: {hex(code_range.base)}-{hex(code_range.end)}"
            )
            self.script.exports_sync.addrange(
                lib, code_range.base, code_range.end
            )
        self.script.exports_sync.instrument()
        self.fuzzer_setup = True

    def fuzzer_cmd(self):
        env = f""
        if self.do_pid_filter:
            env = f"WAIT_PID=1 " + env
        if self.fuzz_debug:
            env = f"DEBUG=1 " + env
        env = f"RELOAD=1 " + env
        cmd = f"cd {FUZZER_PATH} && {env} ./{self.fuzzer_name}"
        cmd += f" --interface {self.target_interface} --log_level error 1 --timeout 30 >{LIBFUZZ_LOG}"
        return cmd

    def start_fuzzer(self):
        cmd = self.fuzzer_cmd()
        logging.info(f"starting fuzzing: {cmd}")
        self.orchestrate_log(f"start fuzzing: {cmd}")
        out, err = adb.execute_privileged_command(
            cmd, device_id=self.device_id, wait_for_termination=False
        )
        time.sleep(0.5)
        pid = self.pull_pid()
        if pid is None:
            self.orchestrate_log("ERROR failed to pull .pid file...")
            logging.error(f"ERROR failed to pull .pid file...")
            return
        self.fuzzer_pid = pid
        self.orchestrate_log(f"Fuzzer PID: {self.fuzzer_pid}")
        if self.do_pid_filter:
            logging.info(f"starting pid filter")
            self.script.exports_sync.filterpids(self.fuzzer_pid)
            logging.debug(f"acknowledging pid retrieval")
            adb.execute_privileged_command(
                f"touch {PID_ACK_PATH}", device_id=self.device_id
            )

    def stop_fuzzer(self):
        self.line_printed = 0
        os.system(f'rm {os.path.join(self.fuzz_out_dir, "log.txt")}')#TODO maybe backup
        adb.execute_privileged_command(
            f"rm {LIBFUZZ_LOG}", device_id=self.device_id
        )
        logging.info(f"killing fuzzer")
        adb.execute_privileged_command(
            f"kill -9 {self.fuzzer_pid}", device_id=self.device_id
        )

    def do_frida_cleanup(self):
        try:
            self.script.unload()
            print(f"[*] script unloaded")
            self.process.detach()
            print(f"[*] detached from device..")
        except frida.InvalidOperationError:
            logging.warning(f"script already destroyed")
            print(f"{PURPLE} script already destroyed ...{NC}")

    def frida_cleanup(self):
        cleanup_t = threading.Thread(target=self.do_frida_cleanup)
        cleanup_t.daemon = True
        cleanup_t.start()
        cleanup_t.join(10)
        if cleanup_t.is_alive():
            print("[*] long time during frida cleanup, exiting now")

    def check_timeout(self):
        out, err = adb.execute_privileged_command(
            f"ls {FUZZER_PATH} | grep timeout-", 
            device_id=self.device_id
        )
        if b"timeout-" in out:
            return True
        return False

    def fuzzer_iteration(self):
        do_log = True
        if not self.fuzzer_running():
            timed_out = self.check_timeout()
            if timed_out:
                self.store_timeout()
                self.orchestrate_log(f"timed out, killing service")
                adb.execute_privileged_command(f'kill -9 {self.service.pid}', device_id=self.device_id)
                adb.execute_privileged_command(f'rm {FUZZER_PATH}/timeout-*', device_id=self.device_id)
                time.sleep(2)
            device_ok = self.check_device()
            service_ok = self.check_service()
            if service_ok and device_ok:
                if self.iteration > 0:
                    self.renew_frida_device()
                self.setup_script(frida_script, orch.on_message)
                self.setup_fuzzer(iteration=self.iteration)
                self.start_fuzzer()
                self.orchestrate_log(f"fuzzer pid: {self.fuzzer_pid}")
            if device_ok and not service_ok:
                # service has crashed
                logging.info(
                    "[ORC] Service pid is gone, waiting for service to restart"
                )
                self.orchestrate_log(
                    "Service pid is gone, waiting for service to restart"
                )
                self.pull_fuzzdata()
                self.print_status(
                    self.time_running, 
                    self.nr_service_crashed, 
                    self.nr_device_borked,
                    full=True
                )
                self.stop_fuzzer()
                self.pull_logcat()
                self.frida_injected = False
                self.frida_ready = False
                self.fuzzer_setup = False
                self.nr_service_crashed += 1
                self.service.wait_for_service()
                self.service.adb_data()
                logging.info(f"[ORC] Service has restarted {self.service.pid}")
                self.orchestrate_log(
                    f"Service has restarted {self.service.pid}"
                )
                adb.clear_logcat(device_id=self.device_id)
                #do_log = False
            if not device_ok:
                adb.clear_logcat(device_id=self.device_id)
                self.nr_device_borked += 1
                self.wait_for_device()
                #do_log = False
        else:
            onTransact_hit = self.onTransact_hook_hit()
            if not onTransact_hit:
                adb.clear_logcat(device_id=self.device_id)
                raise HookNotHit()
            self.pull_fuzzdata()
        return do_log

    def fuzz(self, interval=5, max_device_reboots=1000000, max_service_crashes=1000000):

        self.setup_outdir()

        # runs in an infinite loop or for set amount of time
        # monitors the service and fuzzer, pulls the fuzzer output
        # if service crashed:
        # 1. wait for service to restart and reinstrument
        # 2. restart fuzzer resume current execution
        # if phone gets messed up, wait until service runs again and reset everything
        # for certain devices, if phone is unresponsive prompt user for manual reboot!
        self.start_time = time.time()
        self.store_start_time()
        while self.time_running < self.time_torun:
            do_log = True
            try:
                if self.iteration == 0:
                    # clean-up the fuzzing dir on the device
                    self.fuzz_clean()
                    adb.clear_logcat(device_id=self.device_id)
                do_log = self.fuzzer_iteration()
            except adb.ADBDeviceNotFound:
                logging.warning(
                    f"device not found error... adb.ADBDeviceNotFound"
                )
                self.orchestrate_log(
                    f"device not found error... adb.ADBDeviceNotFound"
                )
                self.store_reboot('adb.ADBDeviceNotFound')
                #do_log = False
                self.nr_device_borked += 1
                self.wait_for_device()
            except adb.DeviceTimeoutException:
                logging.warning("adb.DeviceTImeoutException")
                self.orchestrate_log(
                    f"DeviceTimeoutException service is messed up..."
                )
                self.store_reboot('adb.DeviceTimeoutException')
                self.nr_device_borked += 1
                if IS_EMULATOR:
                    emulator.full_reset(self.device_id)
                else:
                    self.wait_for_device()
                self.renew_frida_device()  
            except adb.ADBTimeoutException:
                logging.warning(f"timeout error")
                self.orchestrate_log(
                    f"timeout error, while waiting for service .. adb.ADBTimeoutException"
                )
                self.store_reboot('adb.ADBTimeoutException')
                self.nr_device_borked += 1
                if IS_EMULATOR:
                    emulator.full_reset(self.device_id)
                else:
                    self.wait_for_device()
                self.renew_frida_device()
            except frida.ServerNotRunningError:
                logging.warning(
                    f"server not running... frida.ServerNotRunningError"
                )
                self.orchestrate_log(
                    f"server not running... frida.ServerNotRunningError"
                )
                #do_log = False
                self.store_reboot('frida.ServerNotRunningError')
                self.nr_device_borked += 1
                self.wait_for_device()
            except frida.TransportError:
                logging.warning(f"server not running... frida.TransportError")
                self.orchestrate_log(
                    f"server not running... frida.TransportError"
                )
                #do_log = False
                self.store_reboot('frida.transportError')
                self.nr_device_borked += 1
                if IS_EMULATOR:
                    emulator.full_reset(self.device_id)
                else:
                    self.wait_for_device()
                self.renew_frida_device() 
            except frida.InvalidOperationError:
                logging.warning(
                    f"device not running... frida.InvalidOperationError {traceback.print_exc()}"
                )
                self.orchestrate_log(
                    f"device not running... frida.InvalidOperationError"
                )
                #do_log = False
                self.store_reboot('frida.InvalidOperationError')
                self.nr_device_borked += 1
                if IS_EMULATOR:
                    emulator.full_reset(self.device_id)
                else:
                    self.wait_for_device()
                self.renew_frida_device()
            except frida.core.RPCException:
                logging.warning(f"unable to instrument stuff..")
                self.orchestrate_log(
                    f"unable to insturment frida.core.RPCException.."
                )
                #do_log = False
                self.store_reboot('frida.core.RPCException')
                self.nr_device_borked += 1
                if IS_EMULATOR:
                    emulator.full_reset(self.device_id)
                else:
                    self.wait_for_device()
                self.renew_frida_device()
                time.sleep(4) # experience shows that this happens when we hooke the service but it hasn't started
            except frida.ProcessNotFoundError:
                logging.warning(
                    f"service not running... frida.ProcessNotFoundError"
                )
                self.orchestrate_log(
                    f"service not running... frida.ProcessNotFoundError"
                )
                self.service.pid = None
                #do_log = False
            except frida.ProcessNotRespondingError:
                logging.warning(f"unable to instrument stuff.. (ProcessNotRespondingError)")
                self.orchestrate_log(
                    f"unable to insturment frida.ProcessNotRespondingError.."
                )
                #do_log = False
                self.store_reboot('frida.ProcessNotRespondingError')
                self.nr_device_borked += 1
                if IS_EMULATOR:
                    emulator.full_reset(self.device_id)
                else:
                    self.wait_for_device()
                    adb.reset_service(self.service.service_name, self.device_id, 
                                 unmount_path=TMPFS)
                self.renew_frida_device()
            except HookNotHit:
                logging.warning(f"frida hook not hit")
                self.orchestrate_log(
                    f"frida hook not hit"
                )
                #do_log = False
                self.store_reboot('HookNotHit')
                self.nr_device_borked += 1
                if IS_EMULATOR:
                    emulator.full_reset(self.device_id)
                else:
                    self.wait_for_device()
                    adb.reset_service(self.service.service_name, self.device_id, 
                                 unmount_path=TMPFS)
                self.renew_frida_device() 
            except adb.ADBDeviceOffline:
                logging.warning(
                    f"device adb is offline"
                )
                self.orchestrate_log(
                    f"device adb is offline"
                )
                self.service_pid = None
                #do_log = False
                self.store_reboot('adb.ADBDeviceOffline')
                self.nr_device_borked += 1
                self.wait_for_device()
                self.renew_frida_device()

            if do_log:
                # print status information at the end of iteration
                self.print_status(
                    self.time_running,
                    self.nr_service_crashed,
                    self.nr_device_borked,
                    full = (self.iteration%100 == 0)
                )
                self.orchestrate_log(
                    f"fuzzing iteration: {self.iteration} time: {self.time_running}, crashes: {self.nr_service_crashed}, device borked: {self.nr_device_borked}"
                )

            time.sleep(interval)
            self.time_running = time.time() - self.start_time
            self.iteration += 1

            if self.nr_device_borked > max_device_reboots:
                self.orchestrate_log(
                    f"{self.nr_device_borked} greater than threshold {max_device_reboots}, exiting! "
                )
                break
            if self.nr_service_crashed > max_service_crashes:
                self.orchestrate_log(
                    f"{self.nr_service_crashed} greater thant threshold {max_service_crashes}"
                )
                break

        self.store_end_time()
        self.stop_fuzzer()
        self.pull_fuzzdata()

        self.print_status(
            self.time_running, self.nr_service_crashed, self.nr_device_borked,
            full=True
        )


if __name__ == "__main__":

    ############################################################################
    # set up argument parser
    ############################################################################

    parser = argparse.ArgumentParser(description=f"Fuzz a native service")
    parser.add_argument(
        "-s",
        "--service_name",
        type=str,
        required=True,
        help="name of native service to fuzz",
    )
    parser.add_argument(
        "-d", "--device", 
        type=str, 
        required=True, 
        help="device to test"
    )
    parser.add_argument(
        "-t",
        "--time",
        type=int,
        required=False,
        default=0x100000000000,
        help="time to fuzz",
    )
    parser.add_argument(
        "--pid_filter",
        required=False,
        default=False,
        action="store_true",
        help="enable the pid filter",
    )
    parser.add_argument(
        "--dont_fuzz",
        required=False,
        default=False,
        action="store_true",
        help="only instrument service so fuzzer is run manually",
    )
    parser.add_argument(
        "--fuzz_debug",
        required=False,
        default=False,
        action="store_true",
        help="enable fuzz debug output",
    )
    parser.add_argument(
        "--max_device_restarts",
        required=False,
        type=int,
        default=100,
        help="set to stop fuzzing after certain number of device shutdowns",
    )
    parser.add_argument(
        "--max_service_restarts",
        required=False,
        type=int,
        default=100,
        help="set to stop fuzzing after certain number of crashes",
    )
    parser.add_argument(
        "--no_reset",
        required=False,
        default=False,
        action="store_true",
        help="don't kill the service before starting to fuzz",
    )
    parser.add_argument(
        "--no_varmap",
        required=False,
        default=False,
        action="store_true",
        help="disable FANS manual variable name to semantic mapping",
    )
    args = parser.parse_args()

    if args.pid_filter:
        print(f'{RED}WARNING WARNING WARNING broken for the pixel 2..')
        exit(-1)

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
    # custom dumpsys handling
    ############################################################################

    if not adb.path_exists(CUSTOM_DUMPSYS_PATH, device_id=args.device):
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
    # reset if necessary
    ############################################################################

    if args.no_reset:
        print("[ORC] no_reset set, not killing service")
    else:
        print("[ORC] resetting device, killing service and waiting for device")
        adb.reset_service(
            args.service_name,
            device_id=args.device,
            timeout=TIMEOUT,
            unmount_path=TMPFS
        )
        print("[ORC] finished reset, starting")

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

    if device.id in PAIN:
        if args.service_name in PAIN[device.id]:
            print(f"{RED}NOT FUZZING DEVICE DESTROYING SERVICE!!!{NC}")
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
    if args.dont_fuzz and args.pid_filter:
        print(
            "[ORC] ERROR: setting both dont_fuzz and pid_filter does not work!!"
        )
        exit(0)

    ############################################################################
    # start orchestrator
    ############################################################################

    orch = FuzzOrchestrator(
        args.service_name,
        device,
        svc,
        binder_db,
        do_pid_filter=args.pid_filter,
        fuzz_debug=args.fuzz_debug,
        torun=args.time,
        meta_device_id=META_TARGET,
        novarmap=args.no_varmap
    )

    if args.dont_fuzz:
        orch.setup_script(frida_script, orch.on_message)
        orch.setup_fuzzer()
        orch.print_fuzzer_cmd()
        sys.stdin.read()
    else:
        print("[ORC] starting fuzzing loop")
        if IS_EMULATOR:
            max_device_reboots = 10000000000
            max_service_crashes = 10000000000
        else:
            max_device_reboots = args.max_device_restarts
            max_service_crashes = args.max_service_restarts
        try:
            orch.fuzz(
                max_device_reboots=max_device_reboots,
                max_service_crashes=max_service_crashes,
            )
        except KeyboardInterrupt:
            orch.orchestrate_log("interrupted by user")
            # TODO: cleanup
            adb.execute_privileged_command(
                f"kill -9  {orch.fuzzer_pid}", device_id=orch.device_id
            )
            orch.frida_cleanup()
            exit(0)
