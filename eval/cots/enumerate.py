import os
import argparse
import logging
import frida
import sys
import subprocess

BASE_PATH = os.path.dirname(__file__)
REPO_BASE = os.path.join(BASE_PATH, "..", "..")
sys.path.append(REPO_BASE)
sys.path.append(os.path.join(REPO_BASE, "instrument"))

import adb
import service.service as service
import emulator.emulator as emulator
from data import database
from config import SKIP_SERVICES
from utils import utils
from config import CYAN, RED, NC, META_TARGET, IS_EMULATOR, SCUFFED_SERVICES

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)


def do_enumeration(
    device_id: str, tries=1, ignore_cache=False, no_system_server=False
):
    if IS_EMULATOR:
        emulator.reset(device_id)
    services = adb.get_services(device_id=device_id)
    binder_db = database.open_db()
    for idx, s in enumerate(services):
        log.info(f"[{idx+1}/{len(services)}] {s}")

        if s in SCUFFED_SERVICES:
            log.info(f"Skipping {s}")
            continue
        if device_id in SKIP_SERVICES and s in SKIP_SERVICES[device_id]:
            log.info(f"Skipping service {s}")
            continue

        cached_service = None

        try:
            if META_TARGET is None:
                cached_service: service.Service = database.get_service(
                    binder_db, s, device_id
                )
            else:
                cached_service: service.Service = database.get_service(
                    binder_db, s, META_TARGET 
                ) 
        except:
            pass

        if cached_service is not None:
            if not ignore_cache and cached_service.onTransact is not None:
                if "libandroid_runtime.so" in cached_service.onTransact.bin:
                    log.info(f'java service {s}, already done, skipping')
                    continue
                local = os.path.join(
                    "/tmp", os.path.basename(cached_service.onTransact.bin)+os.urandom(10).hex()
                )
                if not adb.path_exists(cached_service.onTransact.bin, device_id=device_id):
                    cached_service.wipe_cache()
                else:
                    adb.pull_privileged(
                        cached_service.onTransact.bin, local, device_id=device_id
                    )
                    md5 = utils.get_md5(local)
                    os.system(f'rm {local}')
                    if md5 != cached_service.onTransact.md5:
                        log.error(
                            f"{local} and {cached_service.onTransact.bin} mismatch!"
                        )
                        # the cache is outdated. wipe it and let the remainder of
                        # this script recreate it.
                        cached_service.wipe_cache()
                    else:
                        log.info(f'already done for {s}, skipping')
                        continue

        service_pid = adb.get_service_pid(s, device_id)
        out, err = adb.execute_privileged_command(
            f"ps -A | grep {service_pid}", device_id=device_id
        )
        if b"system_server" in out:
            is_system_server = True
        else:
            is_system_server = False

        if no_system_server:
            if is_system_server:
                print(f"skipping system server")
                continue

        print(f"handling {s} on {device_id}, enumerating...")
        for t in range(0, tries):
            if IS_EMULATOR:
                emulator.reset(device_id)
            else:
                #adb.reset_service(s, device_id=device_id, do_kill_Frida=False, timeout=2*60)
                if len(adb.get_services(device_id)) < 10:
                    print(f"service manager is fucked, rebooting")
                    adb.reboot(device_id)
                    adb.wait_for_device(device_id)
                if t > 0:
                    print(f"handling {s} on {device_id}, resetting")
                    #adb.reset_service(s, device_id=device_id, timeout=2*60)
            cmd = f"python3 {REPO_BASE}/instrument/interface.py -s {s} -d {device_id}"
            if ignore_cache:
                cmd += " --ignore_cache"

            print(f"{s} is ready, attempting to get onTransact with {cmd}")

            try:
                out = subprocess.check_output(cmd, shell=True)
            except subprocess.CalledProcessError as e:
                log.error(e)

            if is_system_server:
                # reboot after system server
                if not IS_EMULATOR:
                    adb.reboot(device_id=device_id)
                    adb.wait_for_device(device_id=device_id)

            try:
                if META_TARGET is not None:
                    s_enum = database.get_service(binder_db, s, META_TARGET)
                else:
                    s_enum = database.get_service(binder_db, s, device_id)
                if s_enum is None:
                    log.error(f"failed to retrieve service from db")
                    continue
                if s_enum.onTransact.entry_addr != -1:
                    log.info(f"{CYAN}finished enumerating: {s_enum.onTransact}{NC}")
                    break
            except Exception as e:
                log.error(f"failed to retrieve service from db: {str(e)}")
                continue


def build_parser():
    parser = argparse.ArgumentParser(
        description=f"given a device try enumerating all services"
    )
    parser.add_argument(
        "--ignore_cache",
        required=False,
        default=False,
        action="store_true",
        help="don't use cached results in db",
    )
    parser.add_argument(
        "-d",
        "--device",
        required=True,
        type=str,
        default=None,
        help="specify device",
    )
    parser.add_argument(
        "-t",
        "--tries",
        required=False,
        type=int,
        default=3,
        help="how many times to try a given service",
    )
    parser.add_argument(
        "--no_system_server",
        required=False,
        default=False,
        action="store_true",
        help="ignore services from the system server",
    )
    parser.add_argument(
        "--ignore_list",
        type=str,
        required=False,
        default="",
        help="comma-seperated list of services to ignore: s1,s2,s3",
    )

    return parser


if __name__ == "__main__":

    parser = build_parser()
    args = parser.parse_args()

    devices = frida.enumerate_devices()

    possible_devices = [
        d for d in devices if d.type == "usb" and not "ios" in d.name.lower()
    ]

    device = None
    if args.device is not None:
        # if user gave us a device id, we look for this device
        if args.device not in [d.id for d in possible_devices]:
            print(f"{RED}[-] device not connected!{NC}")
            print(
                f"connected devices: ",
                ",".join([d.id for d in possible_devices]),
            )
        else:
            device = [d for d in possible_devices if d.id == args.device][0]
    else:
        # if user did not give us a device id, we choose the first device
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
        print(f"{RED}[-] device is None{NC}")
        exit(-1)

    if args.ignore_list != "":
        ignore_list = []
    else:
        ignore_list = args.ignore_list.split(",")

    do_enumeration(
        device.id,
        tries=args.tries,
        ignore_cache=args.ignore_cache,
        no_system_server=args.no_system_server,
    )
