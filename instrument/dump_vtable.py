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
    BINDER_KNOWN_CMDS,
    TARGET_DIR
)
import service.vanilla as vanilla
import data.database as database
import utils.utils as utils
import emulator.emulator as emulator
import adb
from instrument.hook import ServiceHooker

MAX_ENTRIES = 100

NON_NULL_VALUE = 0x400

RED = "\033[0;31m"
YELLOW = "\033[0;33m"
GREEN = "\033[0;32m"
NC = "\033[0m"
BLUE = "\033[0;34m"
PURPLE = "\033[0;35m"
CYAN = "\033[0;36m"

DUMP_SCRIPT = os.path.join(BASE_DIR, "fridajs", "vtable_dump.js")

TIMEOUT = 10 * 60

logging.basicConfig(
    filename=os.path.join(BASE_DIR, "vtable_dump.log"),
    encoding="utf-8",
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(filename)s.%(funcName)s %(message)s",
    force=True,
)


class VtableDumper(ServiceHooker):
    def __init__(
        self, servicename, device, svc_obj, binder_db, meta_device_id=None
    ) -> None:
        super().__init__(servicename, device, "vanilla", svc_obj, meta_device_id=meta_device_id)
        self.frida_ready = False
        self.binder_db = binder_db
        self.dump_script = DUMP_SCRIPT
        self.vtable_dump = None

    def log(self, line):
        print(f"[DMP][{self.device_id}] {line}")
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

    def dump_info(self):
        if META_TARGET:
            out_path = os.path.join(TARGET_DIR, META_TARGET, self.service.service_name, 'onTransact_vtable.txt')
        else:
            out_path = os.path.join(TARGET_DIR, self.device_id, self.service.service_name, 'onTransact_vtable.txt')
        with open(out_path, 'w+') as f:
            for off, data in self.vtable_dump.items():
                f.write(f'0x{off}\t{hex(data["offset"])}\t{data["module"]}\n')

    def dump(self):
        self.log("loading frida script")
        self.setup_script(self.dump_script, self.on_message_dump)
        self.script.load()
        while not self.frida_ready:
            self.log("waiting for frida script to come up...")
            time.sleep(1)
        # set onTransact binary
        self.script.exports_sync.setonstransact(
            self.service.onTransact.entry_addr,
            os.path.basename(self.service.onTransact.bin),
            self.service.onTransact.BBinder_path,
            self.service.onTransact.module
        )    
        self.script.exports_sync.instrument()
        adb.execute_privileged_command(f'service call {self.service.service_name} 69', device_id=self.device_id)
        time.sleep(1)
        if self.vtable_dump is None:
            print(f'{RED} dumping fialed..{NC}')
        print(self.vtable_dump)
        self.dump_info()
        self.frida_cleanup()

    def on_message_dump(self, message, data):
        self.log(f"on_message: {message}")
        if message["type"] == "send":
            payload = json.loads(message["payload"])
            if "type" in payload:
                payload_type = payload["type"]
                if payload_type == "setup_done":
                    self.frida_ready = True
            else:
                self.vtable_dump = payload   


if __name__ == "__main__":

    ############################################################################
    # set up argument parser
    ############################################################################

    parser = argparse.ArgumentParser(
        description=f"Dump vtable of service"
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
    args = parser.parse_args()

    device_id = args.device
    service_name = args.service_name

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

    print("[DMP] resetting device, killing service and waiting for device")
    adb.reset_service(service_name, device.id)
    print("[DMP] finished reset, continuing")

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

    vtd = VtableDumper(service_name, device, svc, binder_db, meta_device_id=META_TARGET)
    vtd.dump()
    
