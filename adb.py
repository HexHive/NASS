import re
import subprocess
import time
import logging
import sys
import os
import string
import random
from frida import ServerNotRunningError
import traceback
import emulator.emulator as emulator

from config import IS_ANDROID_28, CUSTOM_DUMPSYS_PATH, FANS_PIXEL_2_XL, IS_EMULATOR

log = logging.getLogger(__name__)


class DeviceTimeoutException(Exception):
    def __init__(self, stdout, stderr) -> None:
        self.stdout = stdout
        self.stderr = stderr


class ADBSetTimeException(Exception):
    pass


class ADBTimeoutException(Exception):
    pass


class ADBPushNoFile(Exception):
    pass


class ADBDeviceNotFound(Exception):
    pass

class ADBDeviceOffline(Exception):
    pass

def subprocess_adb(cmd, device_id, wait_for_termination=True):
    if device_id:
        cmd.insert(0, device_id)
        cmd.insert(0, "-s")
    cmd.insert(0, "adb")
    try:
        p = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stdin=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
    except OSError as e:
        print(traceback.format_exc())
        log.error("Did you add adb to your $PATH?")
        sys.exit(1)
    return p


def call_adb(
    cmd, device_id, wait_for_termination=True, timeout=None, do_log=True
):
    if do_log:
        logging.debug(
            f">>>[{device_id}]>>> calling adb function with command: "
            + str(cmd)
        )
    p = subprocess_adb(cmd, device_id, wait_for_termination)
    if not wait_for_termination:
        return None, None
    try:
        out, err = p.communicate(timeout=timeout)
        p.wait()
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout
        p.terminate()
        raise DeviceTimeoutException(exc.stdout, exc.stderr)
    if f"error: device '{device_id}' not found".encode() in err:
        raise ADBDeviceNotFound()
    if f"device offline".encode() in err:
        raise ADBDeviceOffline()
    return out, err


def subprocess_privileged(cmd, device_id):
    """Get subprocess of privileged command"""
    p = subprocess_adb(["shell", "su -c '{}'".format(cmd)], device_id=device_id)
    time.sleep(2)
    if p.poll():
        p = subprocess_adb(
            ["shell", "su root {}".format(cmd)], device_id=device_id
        )
    if p.poll():
        log.error(f">>>[{device_id}]>>> error creating privileged subprocess.")
        p = None
    return p


def execute_privileged_command(
    cmd, device_id, wait_for_termination=True, timeout=None, do_log=True
):
    """Executes the given privileged command on the device"""
    if (
        device_id in FANS_PIXEL_2_XL
        or (type(device_id) == bytes and b"emulator" in device_id)
        or (type(device_id) == str and "emulator" in device_id)
    ):
        out, err = call_adb(
            ["shell", "su root sh -c '{}'".format(cmd)],
            device_id=device_id,
            wait_for_termination=wait_for_termination,
            timeout=timeout,
            do_log=do_log,
        )
    else:
        out, err = call_adb(
            ["shell", "su -c '{}'".format(cmd)],
            device_id=device_id,
            wait_for_termination=wait_for_termination,
            timeout=timeout,
            do_log=do_log,
        )
    if err:
        log.debug(
            f">>>[{device_id}]>>> error executing privileged cmd. err: {err}"
        )
    return out, err


def execute_runas_command(
    cmd, device_id, user, wait_for_termination=True, timeout=None, do_log=True
):
    """Executes the given privileged command on the device"""
    if (
        device_id in FANS_PIXEL_2_XL
        or (type(device_id) == bytes and b"emulator" in device_id)
        or (type(device_id) == str and "emulator" in device_id)
    ):
        out, err = call_adb(
            ["shell", "su {} sh -c '{}'".format(user, cmd)],
            device_id=device_id,
            wait_for_termination=wait_for_termination,
            timeout=timeout,
            do_log=do_log,
        )
    else:
        out, err = call_adb(
            ["shell", "su {} -c '{}'".format(user, cmd)],
            device_id=device_id,
            wait_for_termination=wait_for_termination,
            timeout=timeout,
            do_log=do_log,
        )
    if err:
        log.debug(
            f">>>[{device_id}]>>> error executing command as {user} cmd. err: {err}"
        )
    return out, err


def execute_nobody_command(
    cmd, device_id, wait_for_termination=True, timeout=None
):
    """Executes the given privileged command on the device"""
    if (type(device_id) == bytes and b"emulator" in device_id) or (
        type(device_id) == str and "emulator" in device_id
    ):
        out, err = call_adb(
            ["shell", "su nobody sh -c '{}'".format(cmd)],
            device_id=device_id,
            wait_for_termination=wait_for_termination,
            timeout=timeout,
        )
    else:
        out, err = call_adb(
            ["shell", "su nobody -c '{}'".format(cmd)],
            device_id=device_id,
            wait_for_termination=wait_for_termination,
            timeout=timeout,
        )
    if err:
        log.debug(f">>>[{device_id}]>>> error executing nobody cmd. err: {err}")
    return out, err


def execute_command(cmd, device_id, wait_for_termination=True, timeout=None):
    """Executes the given command on the device. If given, device_id is passed to adb -s option"""
    out, err = call_adb(
        ["shell", "{}".format(cmd)],
        device_id=device_id,
        wait_for_termination=wait_for_termination,
        timeout=timeout,
    )
    return out, err


def list_devices():
    """Lists connected devices"""
    out, err = call_adb(["devices"], device_id=None)
    return out


def get_device_ids():
    """Returns a list of device ids.

    Only device ids of devices that allow access are returned.
    """
    ids = []
    out = list_devices()
    lines = out.split(b"\n")
    for line in lines:
        tokens = line.split(b"\t")
        if len(tokens) == 2 and tokens[1] == b"device":
            ids.append(tokens[0].decode())
    return ids


def push(what, where, device_id):
    """Push to the device"""
    out, err = call_adb(["push", what, where], device_id=device_id)
    return out


def push_privileged(
    what, where, device_id, is_directory=False, do_log=False
):
    logging.info(f">>>[{device_id}]>>> uploading {what} to {where}")
    if not os.path.exists(what):
        logging.error(
            f">>>[{device_id}]>>> trying to push non-existent file: {what}"
        )
        raise (ADBPushNoFile(f"trying to push non-existent file: {what}"))
        return None, "no_file"
    """ Push to the device """
    rand_str = list(string.ascii_letters)
    random.shuffle(rand_str)
    workdir = os.path.join("/data/local/tmp", "".join(rand_str[:10]))

    what_file = os.path.basename(what)
    workdir_file = os.path.join(workdir, what_file)

    execute_privileged_command(
        " ".join(["mkdir", workdir]), device_id=device_id, do_log=do_log
    )
    execute_privileged_command(
        " ".join(["chown", "shell:shell", workdir]),
        device_id=device_id,
        do_log=do_log,
    )

    out, err = call_adb(
        ["push", what, workdir], device_id=device_id, do_log=do_log
    )

    if is_directory:
        execute_privileged_command(
            " ".join(["chown", "-R", "shell:shell", workdir_file]),
            device_id=device_id,
            do_log=do_log,
        )
        execute_privileged_command(
            " ".join(["cp", "-r", workdir_file, where]),
            device_id=device_id,
            do_log=do_log,
        )
    else:
        execute_privileged_command(
            " ".join(["chown", "shell:shell", workdir_file]),
            device_id=device_id,
            do_log=do_log,
        )
        execute_privileged_command(
            " ".join(["cp", workdir_file, where]),
            device_id=device_id,
            do_log=do_log,
        )

    execute_privileged_command(
        " ".join(["rm", "-rf", workdir]), device_id=device_id, do_log=do_log
    )

    return out, err


def get_service_pid(service, device_id, timeout=60 * 5):
    if device_id in FANS_PIXEL_2_XL or IS_ANDROID_28:
        # @FANS special handling for getting the service pid
        out, err = execute_privileged_command(
            f"{CUSTOM_DUMPSYS_PATH} {service}",
            device_id=device_id,
            timeout=timeout,
        )
        if err != b"":
            return None
        try:
            return int(out.decode().strip("\n"))
        except ValueError:
            return None
    else:
        out, err = execute_privileged_command(
            f"dumpsys --pid {service}", device_id=device_id, timeout=timeout
        )
        if err != b"":
            return None
        try:
            return int(out.decode().strip("\n"))
        except ValueError:
            return None


def kill_service(service, device_id, timeout=None):
    service_pid = get_service_pid(service, device_id=device_id, timeout=timeout)
    if service_pid is None:
        return
    execute_privileged_command(f"kill -9 {service_pid}", device_id=device_id, timeout=timeout)


def pull(what, where, device_id):
    """Pull from the device"""
    out, err = call_adb(["pull", what, where], device_id=device_id)
    return out


def reboot(device_id):
    if IS_EMULATOR:
        emulator.restart_emulator(device_id)
    else:
        execute_privileged_command(f"reboot", device_id=device_id)


def pull_privileged(what, where, device_id, is_directory=False, do_log=False):
    """Pull from the device"""
    logging.info(f">>>[{device_id}]>>> downloading {what} to {where}")
    rand_str = list(string.ascii_letters)
    random.shuffle(rand_str)
    workdir = os.path.join("/data/local/tmp", "".join(rand_str[:10]))
    what_file = os.path.basename(what)
    workdir_file = os.path.join(workdir, what_file)

    execute_privileged_command(
        " ".join(["mkdir", workdir]), device_id=device_id, do_log=do_log
    )
    if is_directory:
        execute_privileged_command(
            " ".join(["cp", "-r", what, workdir]),
            device_id=device_id,
            do_log=do_log,
        )
        execute_privileged_command(
            " ".join(["chown", "-R", "shell:shell", workdir_file]),
            device_id=device_id,
            do_log=do_log,
        )
    else:
        execute_privileged_command(
            " ".join(["cp", what, workdir]), device_id=device_id, do_log=do_log
        )
        execute_privileged_command(
            " ".join(["chown", "shell:shell", workdir_file]),
            device_id=device_id,
            do_log=do_log,
        )

    out, err = call_adb(
        ["pull", workdir_file, where], device_id=device_id, do_log=do_log
    )
    execute_privileged_command(
        " ".join(["rm", "-rf", workdir]), device_id=device_id, do_log=do_log
    )

    return out


def path_exists(path, device_id, timeout=None):
    """Check if path exists."""
    out, err = execute_privileged_command("ls {}".format(path), device_id=device_id, timeout=timeout)
    if b"No such file" in err or b"No such file" in out:
        return False
    return True


def check_device(device_id, check_space=False):
    out, err = execute_privileged_command("id", device_id=device_id)
    if b"root" not in out:
        return "NOROOT"
    out, err = push_privileged(
        "/etc/hostname", "/data/local/tmp", device_id=device_id
    )
    if b"failed to copy" in out or b"failed to copy" in err:
        return "NOPUSH"

    # TODO: @phil, can you check if we really need g++ on the device?
    # `check_device()` is used in many contexts where we do not need a compiler.
    # out, err = execute_privileged_command(
    #     "/data/data/com.termux/files/usr/bin/g++", device_id=device_id
    # )
    # if b"error: no input files" not in err:
    #     return "NOG++"

    if check_space:
        out, _ = execute_privileged_command(
            'df -h /data | cut -d " "  -f 6', device_id=device_id
        )
        if float(out.strip(b"\n")[:-1]) < 3:
            return "NOSPACE_DATA"
    return "OK"


def is_pid_running(pid, device_id, bin_name=None):
    out, err = execute_privileged_command(f"kill -0 {pid}", device_id=device_id)
    if b"No such process" in err:
        return False
    elif out == b"" and err == b"":
        # for some unholy reason kill -0 may fail...
        if bin_name is not None:
            out, err = execute_privileged_command(
                f"ps -A | grep {bin_name}", device_id=device_id
            )
            if out == b"":
                return False
            else: 
                return True
        return True
    elif b"error: closed" in err:
        raise ADBDeviceNotFound
    elif b"device offline" in err:
        raise ADBDeviceNotFound
    else:
        print(f"[!] WEIRD fuzzer_running?? {out}, {err}")
        return False


def kill_frida(device_id, timeout=None):
    execute_privileged_command(
        f"kill -9 $(pgrep frida-server)", device_id=device_id, timeout=timeout
    )

def get_md5_filehash(file_path, device_id):
    out, err = execute_privileged_command(f'md5sum {file_path}', device_id=device_id)
    if b"" == err:
        return  out.decode().split(" ")[0]
    else:
        return None

def wait_for_device(device_id, log_func=None, log_msg=None, timeout=60 * 60):
    while 1:
        if timeout < 0:
            raise ADBTimeoutException
        if device_id in get_device_ids():
            try:
                if check_device(device_id=device_id) == "OK":
                    return
            except ADBDeviceNotFound:
                pass
        if log_func is not None and log_msg is not None:
            log_func(log_msg)
        else:
            logging.debug(f"waiting for device to reboot...")
        time.sleep(5)
        timeout = timeout - 5


def is_device_offline(device_id):
    out = list_devices()
    lines = out.split(b"\n")
    for line in lines:
        tokens = line.split(b"\t")
        if tokens[0].decode() == device_id:
            if len(tokens) != 2:
                # somethings already fishy here
                return True
            status = tokens[1].decode()
            if status == "offline":
                return True
            return False 
    raise ADBDeviceNotFound

def wait_for_service(service_name, device, timeout=60 * 60):
    while 1:
        if timeout < 0:
            raise ADBTimeoutException
        pid = get_service_pid(service_name, device_id=device)
        if pid is not None:
            time.sleep(0.5)
            return
        logging.debug(f"waiting for {service_name}:{device} to come up")
        time.sleep(3)
        timeout = timeout - 3


def wait_ready(service_name, device_id, timeout=60 * 60):
    while 1:
        if timeout < 0:
            raise ADBTimeoutException
        wait_for_device(device_id, timeout=timeout)
        try:
            wait_for_service(service_name, device_id, timeout=timeout)
            return
        except ADBDeviceNotFound:
            pass
        logging.debug(
            f"waiting for device and service to become ready {service_name}:{device_id}"
        )
        time.sleep(3)
        timeout = timeout - 3


def dont_kill(service_name, device_id, meta_target):
    if meta_target is not None:
        device_id = meta_target
    if device_id in DONT_KILL_SERVICES:
        if service_name in DONT_KILL_SERVICES[device_id]:
            return True
    return False


def reset_service(
    service_name,
    device_id,
    wait=True,
    timeout=60 * 5,
    unmount_path=None,
    do_kill_Frida=True,
    do_kill_service=True,
):
    if IS_EMULATOR:
        emulator.reset(device_id)
        wait_for_device(device_id=device_id, timeout=timeout)
        return
    try:
        # reset a device before running stuff on it
        wait_for_device(device_id=device_id, timeout=timeout)
        if do_kill_Frida:
            kill_frida(device_id=device_id)
        if do_kill_service: 
            kill_service(service_name, device_id=device_id)
        if unmount_path is not None:
            execute_privileged_command(
                f"mount -l {unmount_path}", device_id=device_id
            )
            execute_privileged_command(
                f"rm -rf {unmount_path}", device_id=device_id
            )
        wait_ready(service_name, device_id, timeout=timeout)
    except ADBTimeoutException:
        # service not coming back up, reboot device
        logging.info('service not coming back up rebooting device')
        reboot(device_id=device_id)
        wait_for_device(device_id=device_id, timeout=timeout)
        wait_ready(service_name, device_id, timeout=timeout)

def clear_logcat(device_id):
    execute_privileged_command("logcat -c", device_id=device_id)


def logcat_crashlog(device_id):
    out = subprocess.check_output(
        f"adb -s {device_id} logcat -d '*:F'", shell=True
    )
    return out.decode()


def start_frida(device_id, frida_path):
    execute_privileged_command(
        f"{frida_path} &", wait_for_termination=False, device_id=device_id
    )


def get_service_interface(service_name, device_id):
    out, err = execute_privileged_command(
        f"service list | grep {service_name}", device_id=device_id
    )
    m = re.findall(r"\[(.*)\]", out.decode())
    try:
        return m[0]
    except:
        return None


def is_system_server(pid, device_id):
    out, err = execute_privileged_command(
        f"ps -A | grep {pid}", device_id=device_id
    )
    if b"system_server" in out:
        return True
    return False


def wait_for_frida(device_id, frida_server_path, timeout=60):
    iteration = 0
    resets = 0
    while 1:
        if is_frida_ready(device_id):
            return
        time.sleep(1)
        iteration += 1
        if iteration % 3 == 0:
            if iteration > 8:
                raise ServerNotRunningError
            # something is wrong, restart the server
            log.debug(f"frida not started, killing frida and restarting...")
            kill_frida(device_id=device_id, timeout=60)
            start_frida(device_id=device_id, 
                        frida_path=frida_server_path)


def is_frida_ready(device_id):
    # this can sometime hang... TODO FIXME (handle timeout)
    try:
        result = subprocess.run(
            ["frida", "-D", device_id, "-p", "99999999"],
            capture_output=True,  # Python >= 3.7 only
            text=True,  # Python >= 3.7 only
            timeout=30,
        )
        if "unable to find process" in result.stdout:
            return True
        elif "unable to connect to remote frida-server":
            return False
        print(f"WEIRD UNKNOWN frida code: {result.stdout}")
        return False
    except subprocess.TimeoutExpired:
        log.debug(f"timeout while checking if frida is working...")
        return False


def get_services(device_id: str):
    out, err = execute_privileged_command(
        f"service list", device_id=device_id
    )
    out = out.decode()
    lines = out.split("\n")
    lines = lines[1:]
    services = []
    for l in lines:
        reg_match = re.search(r"\d+[\t]+([a-zA-Z0-9_\-./]+)", l)
        if reg_match is None:
            continue
        services.append(reg_match.group(1))
    return services

def get_hwbinder_services(device_id):
    out, err = execute_privileged_command(
        f"lshal --types b -i --neat", device_id=device_id
    )
    out = out.decode()
    out = out.split("\n")
    services = []
    for l in out:
        p1 = l.split("@")[0]
        p2 = l.split("::")[-1].split("/")[0]
        if p1 == "":
            continue
        services.append(f'{p1}::{p2}')
    return list(set(services))

def get_user_from_pid(pid, device_id):
    out, err = execute_privileged_command(
        f'ps --pid {pid} | cut -d " " -f 1', device_id=device_id
    )
    out = out.decode().split("\n")
    if len(out) < 3:
        return None
    return out[1]
    print(out, err)
