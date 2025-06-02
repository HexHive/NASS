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

CUSTOM_DUMPSYS_PATH = "/data/local/tmp/dumpsys/dumpsys"
BASE_DIR: str = os.path.dirname(__file__)
sys.path.append(os.path.join(BASE_DIR, "..", ".."))

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
    BINDER_KNOWN_CMDS,
    PAIN,
    SKIP_SERVICES,
)
import data.database as database
import data.get_non_default_services as non_default
import emulator.emulator as emulator
import adb
from instrument.hook import ServiceHooker

MAX_ENTRIES = 100

RED = "\033[0;31m"
YELLOW = "\033[0;33m"
GREEN = "\033[0;32m"
NC = "\033[0m"
BLUE = "\033[0;34m"
PURPLE = "\033[0;35m"
CYAN = "\033[0;36m"

IPC_CAPTURE_SCRIPT = os.path.join(BASE_DIR, "ipc_capture.js")

TIMEOUT = 10 * 60

binder_db = database.open_db()

if not os.path.exists(os.path.join(BASE_DIR, "log")):
    os.system(f'mkdir {os.path.join(BASE_DIR, "log")}')

logging.basicConfig(
    filename=os.path.join(BASE_DIR, "log", "ipc_capture.log"),
    encoding="utf-8",
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(filename)s.%(funcName)s %(message)s",
    force=True,
)

"""
script to hook multiple services and capture sent ipc requests
"""

def run_cmd(cmd):
    subprocess.check_output(cmd, shell=True)

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

class ServiceCapture(ServiceHooker):
    def __init__(
        self, servicename, device, svc_obj, output_path, meta_device_id=None
    ) -> None:
        super().__init__(servicename, device, "vanilla", svc_obj, meta_device_id=meta_device_id)
        self.frida_ready = False
        self.servicename = servicename
        self.script = IPC_CAPTURE_SCRIPT 
        self.calls = defaultdict(int)
        self.output_path = os.path.join(output_path, f'{self.device.id}_{self.servicename}.json')
        self.msg_counter = 0

    def log(self, line):
        print(f"[CAPTURE][{self.device_id}] {line}")
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

    def start(self, wait_for_frida):
        self.setup_script(
            self.script, self.capture_on_message, wait_for_frida=wait_for_frida
        )
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
        # start instrumentation
        try:
            self.script.exports_sync.instrument()
        except frida.core.RPCException:
            print(f'{self.servicename} frida RPCException..')
            exit(-1)

    # frida cleanup after finishing

    def capture_on_message(self, message, data):
        #self.log(f"message: {message}, {self.service}")
        self.msg_counter += 1
        if message["type"] == "send":
            payload = json.loads(message["payload"])
            payload_type = payload["type"]
            if payload_type == "setup_done":
                self.frida_ready = True
            elif payload["type"] == "ipcCapture":
                try:
                    command_id = int(payload["command_id"],16)
                except:
                    self.log(f"ERROR weird command id: {payload}")
                    return
                print(f'[CAPTURE]{self.servicename}: {command_id}')
                self.calls[command_id] += 1
            else:
                self.log(f"unknown message {payload}")
        if self.msg_counter % 50 == 0:
            open(self.output_path, 'w+').write(json.dumps(self.calls))


def capture(device, services, output_path):
    capturers = []
    for s in services:
        if META_TARGET is None:
            svc = database.get_service(binder_db, s, device.id)
        else:
            svc = database.get_service(binder_db, s, META_TARGET, 
                                                real_device_id=device.id)
        if svc is None or svc.onTransact is None:
            print(f"[CAPTURE]{s} not in db, skipping..")
            logging.error(f"{s} not in db, skipping..")
            continue
        print(f"[CAPTURE] hooking {s}  on {device.id}")
        try:
            capturers.append(ServiceCapture(
                s, device, svc, output_path, meta_device_id=META_TARGET)
            )
        except Exception as e:
            logging.error(f'exception {e} while setting up..')
            print(f"[CAPTURE] {e} what happened..")
        #TODO remove testinng
        #break
    for i, c in enumerate(capturers):
        if i== 0:
            wait_for_frida = True
        else:
            wait_for_frida = False
        try:
            c.start(wait_for_frida)
        except Exception as e:
            logging.error(f'exception {e} while setting up..')
            print(f"[CAPTURE] {e} what happened..")
    return capturers
   
def hook_running(capturers: list[ServiceCapture], device_id):
    if not device_id in adb.get_device_ids():
        return False
    out, err = adb.execute_privileged_command(f'ps -A | grep frida-server', device_id=device_id)
    if b"frida-server" not in out:
        return False
    nr_not_running = 0
    for c in capturers:
        if not c.frida_injected():
            nr_not_running += 1
        if nr_not_running > 5:
            return False
    return True


def ipc_capture(device, services, capture_time, output_path):
    t1 = time.time()
    out = {} 
    capturers = []
    os.system(f'mkdir {output_path}')
    try:
        while True:
            if time.time() - t1 > capture_time:
                print(f"[CAPTURE] all done ..")
                break
            # hook services again
            if not hook_running(capturers, device.id):
                if device_id in adb.get_device_ids():
                    adb.reboot(device_id)
                update_out(out, capturers)
                adb.wait_for_device(device_id)
                print(f"[CAPTURE] hook not running starting hooks")
                capturers = capture(device, services, output_path) 
            time.sleep(10)
    except KeyboardInterrupt:
        pass
    finally:
        print(f"[CAPTURE] finishing capture ..")
        update_out(out, capturers)
    open(f'{output_path}/final.json', 'w+').write(json.dumps(out))

def update_out(out, capturers: list[ServiceCapture]):
    for c in capturers:
        if c.servicename not in out:
            out[c.servicename] = {}
            out[c.servicename] = c.calls
        else:
            curr = out[c.servicename]
            for cmd_id, cnt in c.calls.items():
                if cmd_id in curr:
                    curr[cmd_id] += cnt
                else:
                    curr[cmd_id] = cnt




if __name__ == "__main__":

    ############################################################################
    # set up argument parser
    ############################################################################

    parser = argparse.ArgumentParser(
        description=f"capture ipc requests sent to services during \
            normal operation"
    )
    parser.add_argument(
        "-d", "--device", type=str, required=True, help="device to test"
    )
    parser.add_argument(
        "-t",
        "--capture_time",
        required=True,
        type=int,
        help="if set will generate random seeds into the fuzz folder"
    )
    parser.add_argument(
        "-o", "--output", type=str, required=True, help="output path"
    )
    args = parser.parse_args()

    device_id = args.device
    
    if device_id not in adb.get_device_ids():
        if IS_EMULATOR:
            print(f'[ORC] emulator starting up')
            emulator.full_reset(args.device) 
        else:
            print(f'{RED} device {args.device} not connected')
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
    # reboot device if not emulator
    ############################################################################ 

    if not IS_EMULATOR:
        print(f'[CAPTURE] rebooting device..')
        adb.reboot(device_id=device_id)
        adb.wait_for_device(device_id=device_id)

    if  NEED_CUSTOM_DUMPSYS:
        remote_path = os.path.dirname(CUSTOM_DUMPSYS_PATH)
        if not adb.path_exists(remote_path, device_id=args.device):
            adb.execute_privileged_command(
                f"mkdir -p {remote_path}", device_id=args.device
            )
            if META_TARGET is None:
                path_to_dumpsys = os.path.join(
                    BASE_DIR, "..", "..", "device", args.device, "dumpsys"
                )
            else:
                path_to_dumpsys = os.path.join(
                    BASE_DIR, "..", "..", "device", META_TARGET, "dumpsys"
                )
            adb.push_privileged(
                path_to_dumpsys, remote_path, device_id=args.device
            )

    ############################################################################
    # which services?
    ############################################################################ 

    if "CAPTURE_SERVICES" in os.environ:
        services = open(os.environ["CAPTURE_SERVICES"]).read().split("\n")
    else:
        services = database.single_select(
            binder_db,
                f'select service_name from service where onTransact_entry!=-1 and \
                    binary_path not LIKE "%app_process64%" and onTransact_bin not \
                    LIKE "%libandroid_runtime.so%" and device=="{device_id}";',
        )
        non_default_services = non_default.get_non_default_services(device_id)
        services = list(set(services).intersection(non_default_services))
        services = filter_services(device_id, services)

    ############################################################################
    # start capturing 
    ############################################################################

    ipc_capture(device, services, args.capture_time, args.output)     

