import frida
import argparse
import os
import logging
import sys
import threading
import time

BASE_PATH = os.path.dirname(__file__)
sys.path.append(os.path.join(BASE_PATH, ".."))

import service.bdsm as bdsm
import service.vanilla as vanilla
import utils.utils as utils
import adb

from config import (
    FRIDA_VERSION,
    FRIDA_SERVER_DIR,
    RED,
    NC,
    PURPLE,
)

frida_svr_path = os.path.join(BASE_PATH, "..", "tools", "frida")
remote_path = "/data/local/tmp/frida"
if len(logging.root.handlers) == 0:
    logging.basicConfig(
        filename=os.path.join(BASE_PATH, "hook.log"),
        encoding="utf-8",
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(filename)s.%(funcName)s %(message)s",
        force=True,
    )


class ServiceHooker:
    def __init__(
        self, servicename, device, caller_type="vanilla", svc_obj=None, meta_device_id=None
    ) -> None:
        if svc_obj is None:
            if caller_type == "bdsm":
                self.service = bdsm.BDSM(servicename, device.id, meta_device_id=meta_device_id)
            elif caller_type == "vanilla":
                self.service = vanilla.Vanilla(servicename, device.id, meta_device_id=meta_device_id)
            else:
                self.service = vanilla.Vanilla(servicename, device.id, meta_device_id=meta_device_id)
        else:
            if caller_type == "bdsm":
                self.service = bdsm.BDSM.fromService(svc_obj)
            elif caller_type == "vanilla":
                self.service = vanilla.Vanilla.fromService(svc_obj)
            else:
                self.service = vanilla.Vanilla.fromService(svc_obj)
            self.service.adb_data()
        self.device = device
        self.device_id = self.device.id
        if meta_device_id is None:
            self.meta_device_id = self.device_id
        else:
            self.meta_device_id = meta_device_id
        self.process = None
        self.script = None

    def setup_script(self, script_path, on_message_func, wait_for_frida=True):
        self.device = utils.renew_frida_device(self.device_id)
        adb.execute_privileged_command("setenforce 0", device_id=self.device_id)
        self.setup_frida(wait_for_frida=wait_for_frida)
        self.service.wait_for_service()
        self.process = self.device.attach(self.service.pid)
        self.script = self.process.create_script(open(script_path).read())
        self.script.on("message", on_message_func)

    def start_script(self):
        try:
            self.script.load()
            sys.stdin.read()
        except KeyboardInterrupt:
            self.script.unload()

    def setup_frida(self, wait_for_frida=True):
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
        _, err = adb.execute_privileged_command(
            f"mkdir -p {remote_path}", device_id=self.device_id
        )
        if err:
            logging.error(
                f"failed setting up directory: {remote_path}, {err}",
                device_id=self.device_id,
            )
            raise Exception
        if frida_bin is None:
            logging.error(f"Download the necessary frida server: frida-server-{FRIDA_VERSION}-android-arm64")
            print(f"{RED}Download the necessary frida server: frida-server-{FRIDA_VERSION}-android-arm64{NC}")
            raise Exception
        frida_svr = os.path.join(FRIDA_SERVER_DIR, frida_bin)
        if not os.path.exists(frida_svr):
            logging.error(f"Download the necessary frida server: {frida_svr}")
            print(f"{RED}Download the necessary frida server: {frida_svr}{NC}")
            raise Exception
        frida_svr_remote = os.path.join(
            remote_path, os.path.basename(frida_svr)
        )
        if not adb.path_exists(frida_svr_remote, device_id=self.device_id):
            adb.push_privileged(
                frida_svr, remote_path, device_id=self.device_id
            )
        adb.execute_privileged_command(
            f"chmod +x {frida_svr_remote}", device_id=self.device_id
        )
        logging.info(f"frida setup on {self.device} at {frida_svr_remote}")
        frida_process = os.path.basename(frida_svr)
        # avoid killing frida
        # adb.execute_privileged_command(f'kill -9 $(pidof {frida_process})', device_id=self.device_id)
        out, err = adb.execute_privileged_command(
            f"ps -A | grep frida-server", device_id=self.device_id, 
            timeout=60
        )
        if "frida-server" not in out.decode():
            # start server
            adb.execute_privileged_command(
                f"{frida_svr_remote} &",
                wait_for_termination=False,
                device_id=self.device_id,
                timeout=60
            )
        time.sleep(1)
        if wait_for_frida:
            logging.info(f"waiting for frida")
            adb.wait_for_frida(
                device_id=self.device_id, frida_server_path=frida_svr_remote
            )

    def on_message_refine(self, message, data):
        print(f"message received: {message}")
        if message["type"] == "send":
            print("[*] {0}".format(message["payload"]))
        else:
            print(message)

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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=f"Hook a service for enumeration"
    )
    parser.add_argument(
        "-s",
        "--service_name",
        type=str,
        required=True,
        help="name of native service to hook",
    )
    parser.add_argument(
        "-c",
        "--caller",
        choices=["vanilla", "bdsm"],
        type=str,
        required=False,
        default="vanilla",
        help="which caller to use",
    )
    parser.add_argument(
        "-l",
        "--frida_script",
        type=str,
        default=f"{BASE_PATH}/fridajs/hook.js",
        required=False,
        help="path to script for hooking",
    )
    parser.add_argument(
        "-d", "--device", type=str, required=True, help="device to test"
    )

    args = parser.parse_args()

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

    hooker = ServiceHooker(args.service_name, device, caller_type=args.caller)
    hooker.setup_script(args.frida_script, hooker.on_message_refine)
    hooker.start_script()
