import subprocess
import sys
import time
import traceback
import logging
import os
from datetime import datetime

log = logging.getLogger(__name__)

"""
script to manage emulators
"""

BASE_DIR: str = os.path.dirname(__file__)
sys.path.append(os.path.join(BASE_DIR, ".."))

from config import (
    IS_ANDROID_28, 
    CUSTOM_DUMPSYS_PATH, 
    META_TARGET, 
    META2DOCKERIMAGE, 
    AARCH64_EMU_28,
    AARCH64_EMU_34,
    IS_EMULATOR
)
import adb

DOCKER_NOT_RUNNING = 1
EMULATOR_NOT_RUNNING = 2
EMULATOR_RUNNING = 3
WAIT_TIME = 60

BANNER = '>>>EMULATOR>>>'

EMU_NAME = 'dev'
if META_TARGET is not None and IS_EMULATOR:
    DOCKER_IMAGE = META2DOCKERIMAGE[META_TARGET]

if 'honeycomb-03' in open('/etc/hostname').read() or 'honeycomb-01' in open('/etc/hostname').read() or META_TARGET == "aarch64emu28":
    FLAGS = '-no-window -no-audio -skip-adb-auth -no-boot-anim -show-kernel -read-only' 
else:
    FLAGS = '-cores 2 -memory 4096 -no-window -no-audio -skip-adb-auth -no-boot-anim -show-kernel -read-only' 

class DockerNotStarted(Exception):
    pass

class DockerNotKilled(Exception):
    pass

class EmulatorNotStarted(Exception):
    pass

def run_cmd(cmd):
    return subprocess.check_output(cmd, shell=True).decode()

def device2ports(device_id):
    # emulator-5554 -> ports 5554,5555
    p1 = int(device_id.split("-")[1])
    return p1, p1+1

def id2cn(device_id):
    return f'docker_{device_id}'

def is_docker_running(device_id):
    container_name = id2cn(device_id)
    return container_name in run_cmd(f'docker  ps -a')

def get_emu_pid(device_id):
    if not is_docker_running(device_id):
        return None
    p1,p2 = device2ports(device_id)
    ps_list = run_cmd(f'docker exec {id2cn(device_id)} ps -eo pid,cmd').split('\n')
    for p in ps_list:
        if f'-ports {p1},{p2}' in p:
            return int(p.strip(" ").split(" ")[0])
    return None

def get_emu_containerId(device_id):
    container_name = id2cn(device_id)
    return run_cmd(f'docker container ls -a | grep {container_name} | cut -d " " -f 1')

def is_emulator_running(device_id):
    if get_emu_pid(device_id) is None:
        return False
    return True

def get_emulator_status(device_id):
    if not is_docker_running(device_id):
        return DOCKER_NOT_RUNNING
    if not is_emulator_running(device_id):
        return EMULATOR_NOT_RUNNING
    return EMULATOR_RUNNING

def start_docker(device_id):
    container_name = id2cn(device_id)
    run_cmd(f'docker run --rm --name {container_name} -d --network host \
            --privileged {DOCKER_IMAGE} tail -f')
    ps = run_cmd(f'docker ps | grep {container_name}')
    if 'Up' and container_name in ps:
        return 
    raise DockerNotStarted

def stop_docker(device_id):
    container_name = id2cn(device_id)
    if not is_docker_running(device_id):
        log.warning(f'{BANNER}[{device_id}] attempt to stop docker but not running')
        return
    for _ in range(0, 100):
        try:
            run_cmd(f'docker kill {container_name}')
        except:
            log.warning(f'error while triyng to kill docker')
        time.sleep(0.5)
        ps = run_cmd(f'docker ps -a')
        if container_name in ps:
            # kill container
            try:
                ct_id = get_emu_containerId(device_id)
                print(ct_id)
                if ct_id != "":
                    run_cmd(f'docker container rm {ct_id}')
            except:
                log.warning(f'error while trying to remove container')
            log.warning(f'docker not killed, waiting...')
            time.sleep(0.5)
            continue
        else: 
            return
    raise DockerNotKilled

def setup_dumpsys(device_id):
    if not IS_ANDROID_28:
        return 
    if not adb.path_exists(CUSTOM_DUMPSYS_PATH, device_id=device_id, timeout=10):
        remote_path = os.path.dirname(CUSTOM_DUMPSYS_PATH)
        adb.execute_privileged_command(
            f"mkdir -p {remote_path}", device_id=device_id, timeout=10
        )
        if META_TARGET is None:
            path_to_dumpsys = os.path.join(
                BASE_DIR, "..", "device", device_id, "dumpsys"
            )
        else:
            path_to_dumpsys = os.path.join(
                BASE_DIR, "..", "device", META_TARGET, "dumpsys"
            )
        adb.push_privileged(path_to_dumpsys, remote_path, device_id=device_id)

def setup_time(device_id):
    timestamp = int(time.time())
    adb.execute_privileged_command(f'date @{timestamp}', device_id=device_id, timeout=5)
    log.info(f'setting time to {timestamp}')

def full_reset(device_id):
    for i in range(0,100): 
        try:
            log.info(f'resettig emulator for {device_id}')
            stop_docker(device_id)
            time.sleep(0.5)
            start_emulator(device_id)
            setup_dumpsys(device_id)
            time.sleep(1)
            log.info(f'finished resetting emulator for {device_id}')
            return
        except Exception as e:
            log.error(f'exception triggered in full_reset: {e}, sleeping for a bit {traceback.format_exc()}')
            time.sleep(2)
        

def reset(device_id):
    for i in range(0,100):
        try:
            log.info(f'resettig emulator for {device_id}')
            kill_emulator(device_id)
            time.sleep(0.5)
            start_emulator(device_id)
            setup_dumpsys(device_id)
            time.sleep(1)
            log.info(f'finished resetting emulator for {device_id}')
            return 
        except Exception as e:
            log.error(f'exception triggered in reset: {e}, sleeping for a bit {traceback.format_exc()}')
            time.sleep(2)


def has_booted(container_name, log_file):
    if META_TARGET == AARCH64_EMU_28:
        return 'init: processing action (sys.sysctl.extra_free_kbytes=*) from (/init.rc:719)' in run_cmd(f'docker exec {container_name} cat {log_file}')
    elif META_TARGET == AARCH64_EMU_34:
        return 'Successfully loaded snapshot' in run_cmd(f'docker exec {container_name} cat {log_file}')
    else:
        return 'Boot completed in' in run_cmd(f'docker exec {container_name} cat {log_file}')

def start_emulator(device_id):
    # there will be a docker container with name docker_deivce_id running
    # check if docker is running
    status = get_emulator_status(device_id)
    if status == DOCKER_NOT_RUNNING:
        log.info(f'{BANNER}[{device_id}] start emulator, need to start docker')
        start_docker(device_id)
    if status == EMULATOR_RUNNING:
        log.warning(f'{BANNER}[{device_id}] emulator already running!')
        return
    container_name = id2cn(device_id)
    p1,p2 = device2ports(device_id)
    log_file = os.path.join('/tmp', f'{datetime.now().strftime("%d_%m_%s_%Y_%H%M%S")}_{device_id}.txt')
    cmd = f'docker exec -d {container_name} /bin/bash -c "setsid emulator @{EMU_NAME} {FLAGS} -ports {p1},{p2} 2>&1 > {log_file}"'
    log.info(f'{BANNER}[{device_id}] starting emulator with command: {cmd}')
    subprocess.Popen(cmd, shell=True)
    time.sleep(1)
    # wait for emulator to finish booting
    t1 = time.time()
    while True:
        if has_booted(container_name, log_file):
            log.info(f'{BANNER}[{device_id}] emulator {device_id} booted!')
            try:
                run_cmd(f'docker exec {container_name} pkill -f /bin/bash')
            except:
                log.warning(f'{BANNER}[{device_id}] failed ot kill bash process..')
            setup_emulator(device_id)
            return device_id
        time.sleep(0.5)
        log.debug(f'{BANNER}[{device_id}] waiting for {device_id} to boot')
        if time.time() - t1 > WAIT_TIME:
            log.warning(f'{BANNER}[{device_id}] emulator not starting full resetting docker!')
            full_reset(device_id)
            break
    status = get_emulator_status(device_id)
    if status != EMULATOR_RUNNING:
        raise EmulatorNotStarted
    # get rid of bash process
    try:
        run_cmd(f'docker exec {container_name} pkill -f /bin/bash')
    except:
        log.warning(f'{BANNER}[{device_id}] failed ot kill bash process..')
    setup_emulator(device_id)
    return device_id

def setup_emulator(device_id):
    t2 = time.time()
    while True:
        try:
            adb.execute_privileged_command('ls', device_id=device_id, timeout=1)
            break
        except:
            time.sleep(0.5)
        if time.time() - t2 > WAIT_TIME:
            log.warning(f'{BANNER}[{device_id}] adb not working waiting for it')
            break 
    setup_time(device_id)
    setup_dumpsys(device_id)

def setup_debugging(device_id):
    termux_tar = os.path.join(BASE_DIR, "com.termux.tar.gz")
    if not os.path.exists(termux_tar):
        log.error(f'{termux_tar} does not exist!')
        return
    adb.push_privileged(termux_tar, "/data/local/tmp", device_id=device_id)
    adb.execute_privileged_command(f'cd /data/data && tar xvf /data/local/tmp/com.termux.tar.gz', device_id=device_id)
    adb.execute_privileged_command(f'rm /data/local/tmp/com.termux.tar.gz', device_id=device_id)

def restart_emulator(device_id):
    for i in range(0,100):
        try:
            log.info(f'{BANNER}[{device_id}] restarting emulator')
            kill_emulator(device_id)
            start_emulator(device_id)
            return
        except Exception as e:
            log.error(f'exeption in restart_emulator: {e}, {traceback.format_exc()}')
            time.sleep(2)

def kill_emulator(device_id):
    status = get_emulator_status(device_id)
    if status == DOCKER_NOT_RUNNING:
        log.warning(f'{BANNER}[{device_id}] attempt to kill emulator but emulator not running')
        return
    container_name = id2cn(device_id)
    emu_pid = get_emu_pid(device_id)
    if emu_pid is None:
        log.warning(f'{BANNER}[{device_id}] emulator {device_id} not running')
        return
    run_cmd(f'docker exec {container_name} kill -9 {emu_pid}')
            
if __name__=="__main__":
    device_id = sys.argv[1]
    start_emulator(device_id)
     

