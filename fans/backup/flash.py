import subprocess
import os
import time
import logging
import argparse

log = logging.getLogger(__name__)

def cmd(cmd):
    log.debug(f"[FLASH] executing {cmd}")
    return subprocess.check_output(cmd, shell=True)

def flash(device_id, build_path, fastboot):
    build_path = os.path.realpath(build_path)
    log.info(f"[FLASH] starting to flash image") 
    os.chdir(build_path)
    if not os.path.exists("android-info.txt"):
        print("android-info.txt missing!!!")
        raise 
    try:
        subprocess.check_output(f'{fastboot} -s {device_id} flashing unlock', stderr=subprocess.STDOUT, shell=True)
    except subprocess.CalledProcessError as e:
        if b"already : unlocked!" in e.output:
            log.debug(f'[FLASH] already unlocked')
    log.info("starting flashing!") 
    print("starting flashing!", build_path, os.path.join(build_path)) 
    os.system(
        f'export ANDROID_PRODUCT_OUT={os.path.abspath(build_path)} && \
        echo $ANDROID_PRODUCT_OUT && \
        {fastboot} -s {device_id} flashall -w',
    )

TIMEOUT = 120

def flashall(device_id, build_path, fastboot):
    fastboot = os.path.realpath(fastboot)
    if device_id.encode() in cmd(f'{fastboot} devices'):
        flash(device_id, build_path, fastboot)
        return
    if device_id.encode() in cmd('adb devices'):
        cmd(f'adb -s {device_id} reboot bootloader')
        s = time.time()
        while device_id.encode() not in cmd(f'{fastboot} devices'):
            time.sleep(5)
            if time.time() - s > TIMEOUT:
                print('Unable to boot into fastboot')
                raise 
        flash(device_id, build_path, fastboot)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=f"reflash a device")
    parser.add_argument(
        "-b",
        "--build_path",
        type=str,
        required=True,
        help="path to AOSP build directory",
    )
    parser.add_argument(
        "-d", "--device", 
        type=str, 
        required=True,
        help="device to flash"
    )
    parser.add_argument(
        "-f", "--fasboot",
        type=str,
        required=True,
        help="path to Android sdk fastboot"
    )
    args = parser.parse_args()
    flashall(args.device, args.build_path, args.fasboot)
