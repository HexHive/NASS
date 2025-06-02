import argparse
import frida
import subprocess
import os
import logging
import sys
import queue
import threading
import time
import json

BASE_PATH = os.path.dirname(__file__)
sys.path.append(os.path.join(BASE_PATH, ".."))
sys.path.append(os.path.join(BASE_PATH, "..", "utils"))

if len(logging.root.handlers) == 0:
    logging.basicConfig(
        filename=os.path.join(BASE_PATH, "interface.log"),
        encoding="utf-8",
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(filename)s.%(funcName)s %(message)s",
        force=True,
    )
log = logging.getLogger(__name__)


from config import (
    LIBRARY_BLOCKLIST, 
    BINDER_FUNCS, 
    FANS_PIXEL_2_XL, 
    CUSTOM_DUMPSYS_PATH, 
    META_TARGET, 
    NEED_CUSTOM_DUMPSYS
)
import data.database as database
from lib import *
import utils.utils as utils
import instrument.interface_calls as interface_calls
from hook import *
import service.service as service

hooker = None  # global for the InterfaceEnumerator object

class InterfaceEnumerator(ServiceHooker):
    def __init__(
        self,
        servicename,
        device,
        call_config,
        hook_script,
        svc_obj=None,
        caller_type="vanilla",
        meta_device_id=None
    ) -> None:
        super().__init__(
            servicename, device, caller_type=caller_type, 
            svc_obj=svc_obj, meta_device_id=meta_device_id
        )
        self.queue = queue.Queue()
        self.call_config = (
            call_config  # contains the info on which service calls to make
        )
        self.caller = None
        self.caller_running = False
        self.bbinder_transact_callbacks = []
        self.stalker_transfom_callbacks = []
        self.stalker_callout_callbacks = []
        self.calls_made = []
        self.current_calls = []  # this call store is reset upon a crash
        self.final_crash_call = None
        self.crashed = False
        self.hook_script = hook_script
        self.enum_done = False
        self.frida_ready = False

    def reset(self):
        # the service has crashed, reset everything
        logging.info(f"resetting hooker after crash")
        self.frida_ready = False
        self.service.adb_data()
        self.crashed = False
        self.current_calls = []

    def clear(self):
        # clear collected data
        self.stalker_transfom_callbacks = []
        self.bbinder_transact_callbacks = []
        self.current_calls = []
        self.calls_made = []
        self.frida_ready = False
        self.crashed = False

    def setup_enumeration(self, check_crashed=True):
        self.setup_script(self.hook_script, self.on_message_refine)
        self.caller = threading.Thread(
            target=self.do_call,
            args=[
                check_crashed,
            ],
        )

    def run_enumeration(self, hook_onTransact=False):
        # self.frida_runner.start()
        self.script.load()
        while not self.frida_ready:
            print("waiting...")
            time.sleep(1)
        if hook_onTransact:
            # call rpc functions of hook script to setup necessary stuff
            self.script.exports_sync.setontransact(
                self.service.onTransact.entry_addr, self.service.onTransact.bin
            )
            self.script.exports_sync.start()
        self.caller.start()
        self.caller.join()
        print(f"[*] caller finished...")
        self.frida_cleanup()

    def check_alive(self):
        self.script.exports_sync.ping()

    def do_call(self, check_crashed=True):
        self.caller_running = True
        # send the messages based on the config
        for call in self.call_config.calls:
            print(
                f"{RED}---caller--- calling {self.service.service_name} {call.cmd_id} {call.args}{NC}"
            )
            logging.info(
                f"---caller--- calling {self.service.service_name} {call.cmd_id} {call.args}"
            )
            try:
                pid, stdout, stderr = self.service.call(
                    call.cmd_id, call.args, user=call.user
                )
                print(f"{RED}called with pid:{pid}{NC}")
            except service.CallTimeout:
                logging.info(f"service call timed out..")
                print(f"{RED}servcie timed out..{NC}")
                # the call we made just crashed the service...
                self.final_crash_call = CallData(call, pid, stdout, stderr)
                self.crashed = True
                self.caller_running = False
                return
            time.sleep(self.call_config.sleep)
            if check_crashed:
                try:
                    self.check_alive()
                except frida.InvalidOperationError:
                    logging.warning(f"service just crashed..")
                    print(f"{RED}service just crashed..{NC}")
                    # the call we made just crashed the service...
                    self.final_crash_call = CallData(call, pid, stdout, stderr)
                    self.crashed = True
                    self.caller_running = False
                    return
            self.current_calls.append(CallData(call, pid, stdout, stderr))
            self.calls_made.append(CallData(call, pid, stdout, stderr))
        time.sleep(
            self.call_config.runner_margin
        )  # sleep a bit to make sure we receive all data
        self.caller_running = False

    def on_message_refine(self, message, data):
        if message["type"] == "send":
            current_thread = threading.current_thread()
            thread_id = current_thread.ident
            print(f"received message: {thread_id}")
            payload = json.loads(message["payload"])
            payload_type = payload["type"]
            print(
                f"{CYAN}---receiver--- received from frida, payload: {payload}{NC}"
            )
            logging.info(
                f"---receiver--- received from frida, payload: {payload}"
            )
            # handle different payloads
            if payload_type == "BBinder_transact_hook":
                data = RecvBBinderData(payload, self.service.proc_map)
                self.bbinder_transact_callbacks.append(data)
            elif payload_type == "stalker_instructions":
                data = RecvStalkerData(payload, self.service.proc_map)
                if data.bt.isvalid:
                    self.stalker_transfom_callbacks.append(data)
            elif payload_type == "stalker_callout_instruction":
                self.stalker_callout_callbacks.append(payload)
            elif payload_type == "setup_done":
                self.frida_ready = True
            else:
                logging.error(f"unknown payload type received: {payload}")

    def post_find_onTransact(self):
        if not self.enum_done:
            print(
                f"{CYAN}post_find_onTransact: need to run enumeration over frida first{NC}"
            )
            return -1
        # with the made calls and received data figure out the onTransact entrypoint
        print(
            f"{CYAN}looking for onTransact function...messages: {len(self.bbinder_transact_callbacks)}, calls: {len(self.calls_made)}{NC}"
        )
        onTransact, local_path = find_onTransact(
            self.service, self.bbinder_transact_callbacks, self.calls_made
        )
        self.service.onTransact = onTransact
        return onTransact, local_path


def get_hook_script_pixel_9(device):
    # for some reason on the pixel 9 BBinder::transact is inlined, so we need a bespoke hook to figure out the onTransact function :'(
    # the hook script is dependent on the exact binary deployed on the device
    # we check the hash of the `libbinder.so` here and terminate if it does not match

    adb.pull_privileged(
        "/system/lib64/libbinder.so", "/tmp/", device_id=device.id
    )

    md5 = (
        subprocess.check_output("md5sum /tmp/libbinder.so", shell=True)
        .decode()
        .split(" ")[0]
    )

    print(md5)
    if md5 != "f512d0d243465c4401073a05300c95d3":
        print(f"[ERROR][{device.id}] UNSUPPOTED VERSION OF LIBBINDER!!")
        print(
            f"** on the Pixel 9 onTransact is inlined and thus our hook does not work properly... (that is why we need a custom library specific hook...)"
        )
        exit(1)
    hook_script = os.path.join(BASE_PATH, "fridajs", "hook_onTransact_47030DLAQ0012N.js")
    print(f"using hook script: {hook_script}")
    return hook_script


def get_hook_script_oneplus(device):
    adb.pull_privileged(
        "/system/lib64/libbinder.so", "/tmp/", device_id=device.id
    )

    md5 = (
        subprocess.check_output("md5sum /tmp/libbinder.so", shell=True)
        .decode()
        .split(" ")[0]
    )

    print(md5)
    if md5 != "700f7e9bf186cd83d4177fdf3918ac91":
        print(f"[ERROR][{device.id}] UNSUPPOTED VERSION OF LIBBINDER!!")
        print(
            f"** on the OnePlus onTransact is inlined and thus our hook does not work properly... (that is why we need a custom library specific hook...)"
        )
        exit(1)
    hook_script = os.path.join(BASE_PATH, "fridajs", "hook_onTransact_a497c295.js")
    print(f"using hook script: {hook_script}")
    return hook_script


def consistency_check(service):
    """Perform consistency checks for this service.

    Call this function when our database (cache) already knows about this
    service to perform sanity checks and repairs. For instance, re-download
    the remote binaries in case they're not present locally.
    """

    # nothing to do if the service is not native
    if not service.is_native:
        return

    v_service = vanilla.Vanilla.fromService(service)
    v_service.adb_data()

    libs = v_service.get_dependencies()
    libs = utils.remove_blocklist(libs, LIBRARY_BLOCKLIST)
    for l in libs:
        remote_vma = v_service.proc_map.get_vmabyname(l)
        log.debug(f"remote path for dependency: {remote_vma}")
        if remote_vma is None:
            log.warning(f"weird, remote path for {l} is None")
            continue
        remote_path = remote_vma.vma_name
        v_service.download_binary(remote_path)


def interface_find_onTransact(
    binder_db, device, service_name, ignore_cache=False, clear=False
):
    """Try to find the `onTransact` function in service `service_name`."""

    if device.id == "47030DLAQ0012N":
        # special handling for pixel 9
        hook_script = get_hook_script_pixel_9(device)
    elif device.id == "a497c295":
        hook_script = get_hook_script_oneplus(device)
    else:
        hook_script = os.path.join(BASE_PATH, "fridajs", "hook_onTransact.js")

    if device.id in FANS_PIXEL_2_XL or NEED_CUSTOM_DUMPSYS:
        remote_path = os.path.dirname(CUSTOM_DUMPSYS_PATH)
        adb.execute_privileged_command(
            f"mkdir -p {remote_path}", device_id=device.id
        )
        if META_TARGET is None:
            path_to_dumpsys = os.path.join(
                BASE_PATH, "..", "device", device.id, "dumpsys"
            )
        else:
            path_to_dumpsys = os.path.join(
                BASE_PATH, "..", "device", META_TARGET, "dumpsys"
            ) 
        adb.push_privileged(path_to_dumpsys, remote_path, device_id=device.id)

    # TODO: @phil, what is this magic hex value `0x5F504944`?
    call_config = interface_calls.gen_callconfig_onTransact(
        cmd_ids=[0x5F504944], repetitions=1
    )

    if ignore_cache:
        prev_svc = None
    else:
        if META_TARGET is None:
            prev_svc = database.get_service(binder_db, service_name, device.id)
        else:
            prev_svc = database.get_service(binder_db, service_name, META_TARGET, 
                                            real_device_id=device.id)

    if (
        prev_svc is not None
        and prev_svc.onTransact is not None
        and not ignore_cache
    ):
        print(f"{PURPLE}found onTransact(cached): {prev_svc.onTransact}{NC}")
        consistency_check(prev_svc)
        return prev_svc.onTransact

    print(f"{PURPLE}Interface Enumerator, setting up for onTransact{NC}")
    hooker = InterfaceEnumerator(
        service_name, device, call_config, hook_script, svc_obj=prev_svc, 
        meta_device_id=META_TARGET
    )
    database.insert_update_service(binder_db, hooker.service)
    """
    if not hooker.service.is_native:
        print(f'{PURPLE}Interface enumeration for non-native service not supported (TODO){NC}')
        exit(1)
    """
    hooker.setup_enumeration(check_crashed=False)

    print(
        f"{PURPLE}Interface Enumerator, starting enumeration with {len(call_config.calls)} calls{NC}"
    )

    hooker.run_enumeration()

    print(
        f"{PURPLE}Interface Enumerator, starting post processing with {len(call_config.calls)} calls for onTransact{NC}"
    )

    hooker.enum_done = True
    onTransact, local_path = hooker.post_find_onTransact()
    service_id = database.insert_update_service(binder_db, hooker.service)

    print(f"{PURPLE}Found onTransact function {onTransact}{NC}")
    print(
        f"{PURPLE}Extracting the binder function addresses from {local_path}{NC}"
    )

    if local_path.endswith("libandroid_runtime.so"):
        return onTransact

    interface_extract_deserializers(
        binder_db, service_id, local_path, hooker.service, hooker.device_id
    )

    # TODO: @Phil, why does this function return this object?
    return onTransact


def interface_extract_deserializers(
    binder_db, service_id, local_path, service, device
):
    """
    after we know the binary with the onTransact function, figure out the
    addresses
    """
    deserializers = utils.extract_parcel_deserializations(local_path)
    database.clear_binderfunc(binder_db, service_id)
    for mangled, demangled, func_name in deserializers:
        logging.debug(f"extracting function type from {mangled}")
        binder_func_type = utils.find_binder_func(BINDER_FUNCS, func_name)
        if binder_func_type is None:
            logging.error(f"!!!UNKNOWN BINDER FUNCTION!!! {func_name}")
            continue
        logging.debug(f"binder func type used: {binder_func_type}")
        database.insert_update_binderfunc(
            binder_db, service_id, binder_func_type, mangled, demangled, -1
        )
    print(f"[.] binder function used: {[v[0] for v in deserializers]}")
    if len(deserializers) == 0:
        print(
            f"[.] no binder functions in onTransact binary, grabbing functions from dependencies"
        )
        logging.info(
            f"[.] no binder functions in onTransact binary, grabbing functions from dependencies"
        )

        libs = service.get_dependencies()
        libs = utils.remove_blocklist(libs, LIBRARY_BLOCKLIST)
        found = []
        for l in libs:
            remote_vma = service.proc_map.get_vmabyname(l)
            logging.debug(f"remote path for dependency: {remote_vma}")
            if remote_vma is None:
                logging.warning(f"weird, remote path for {l} is None")
                continue
            remote_path = remote_vma.vma_name
            local_path = service.download_binary(remote_path)
            logging.debug(f"extracting binder deserializers from {local_path}")
            deserializers = utils.extract_parcel_deserializations(local_path)
            for mangled, demangled, func_name in deserializers:
                logging.debug(f"extracting function type from {mangled}")
                if mangled in found:
                    continue
                binder_func_type = utils.find_binder_func(
                    BINDER_FUNCS, func_name
                )
                logging.debug(f'inserting {binder_func_type} into db')
                database.insert_update_binderfunc(
                    binder_db,
                    service_id,
                    binder_func_type,
                    mangled,
                    demangled,
                    -1,
                )
                found.append(mangled)


def wait_for_device(device_id):
    found = False
    for _ in range(0, 10):
        if (
            device.id.encode() in adb.list_devices()
            and adb.check_device(device_id=device.id) == "OK"
        ):
            found = True
            break
        else:
            time.sleep(1)
    # rerefesh frida device
    if not found:
        return None
    new_dev = utils.renew_frida_device(device.id)
    if new_dev is not None:
        device = new_dev
    return device


def wrap_find_onTransact(
    binder_db, device, service_name, ignore_cache=False, clear=False
):
    """A wrapper function for `interface_find_onTransact()` to deal with all the
    crazy ways this function can fail.
    """

    attempts = 2
    while 1:
        try:
            interface_find_onTransact(
                binder_db, device, service_name, ignore_cache=ignore_cache
            )
            logging.info(f"success")
            break
        except frida.NotSupportedError as e:
            if "unable to locate Android dynamic linker" in str(e):
                print(
                    f"{RED} device is messed up frida.NotSupportedError({str(e)}){NC} exiting.."
                )
                logging.error(f"frida.NotSupportedError({str(e)})")
                raise frida.NotSupportedError(str(e))
            if attempts == 0:
                raise frida.NotSupportedError(str(e))
            print(f"{RED} frida.NotSupportedError {str(e)}{NC}")
            attempts -= 1
            print(f"[*] killing the service and sleeping")
            logging.error(
                f"frida.NotSupportedError, attempts: {attempts}, killing service and sleeping 10"
            )
            adb.kill_service(service_name, device_id=device.id)
            adb.kill_frida(device_id=device.id)
            time.sleep(10)
        except frida.TransportError as e:
            if attempts == 0:
                raise frida.TransportError(str(e))
            attempts -= 1
            print(f"{RED}frida.TransportError {str(e)} {NC} {attempts}")
            print(f"[*] killing frida")
            logging.error(
                f"frida.TranspotError, attempts: {attempts}, killing frida and sleeping for 2"
            )
            time.sleep(2)
            try:
                adb.kill_frida(device_id=device.id)
            except:
                print(f"device is also gone...")
                time.sleep(2)
        except adb.ADBDeviceNotFound as e:
            if attempts == 0:
                raise adb.ADBDeviceNotFound(str(e))
            attempts -= 1
            print(f"{RED}adb.ADBDeviceNotFound {str(e)} {NC} {attempts}")
            print(f"[*] waiting for device")
            device = wait_for_device(device.id)
        except frida.ServerNotRunningError as e:
            if attempts == 0:
                raise frida.ServerNotRunningError(str(e))
            attempts -= 1
            print(f"{RED}frida.ServerNotRunningError {str(e)} {NC} {attempts}")
            print(f"[*] killing frida and sleeping")
            adb.kill_frida(device_id=device.id)
            time.sleep(2)
        except frida.ProcessNotFoundError as e:
            if attempts == 0:
                raise frida.ProcessNotFoundError(str(e))
            attempts -= 1
            print(f"{RED}frida.ProcessNotFoundError {str(e)} {NC} {attempts}")
            print(f"[*] killing frida and sleeping")
            adb.kill_frida(device_id=device.id)
            time.sleep(2)
        except frida.InvalidOperationError as e:
            if attempts == 0:
                raise frida.InvalidOperationError(str(e))
            attempts -= 1
            print(f"{RED}frida.InvalidOperationError {str(e)} {NC} {attempts}")
            print(f"[*] killing frida and renewing device and sleeping")
            new_dev = utils.renew_frida_device(device.id)
            if new_dev is not None:
                device = new_dev
            time.sleep(2)
    # cleanup
    # try:
        # adb.kill_frida(device_id=device.id)
    # except:
        # pass  # iggnore devicenotfound


def build_parser():
    parser = argparse.ArgumentParser(
        description=f"Hook a service for enumeration, enumerate the interface"
    )
    parser.add_argument(
        "-s",
        "--service_name",
        type=str,
        required=True,
        help="name of native service to hook",
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
    return parser


if __name__ == "__main__":

    parser = build_parser()
    args = parser.parse_args()
    binder_db = database.open_db()

    devices = frida.enumerate_devices()
    # filter for usb and non-ios devices
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

    wrap_find_onTransact(
        binder_db, device, args.service_name, ignore_cache=args.ignore_cache
    )
