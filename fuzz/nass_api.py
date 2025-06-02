import logging 
import re
import subprocess
from typing import Optional
import os
import sys

BASE_DIR: str = os.path.dirname(__file__)
sys.path.append(os.path.join(BASE_DIR, ".."))

import adb

log = logging.getLogger(__name__)

class NoRefineDir(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

BANNER = ">>>[NASS-ORCH]>>>"
BANNER_TRIAGE = ">>>[NASS-TRIAGE]>>>"
BANNER_PREPROC = ">>>[NASS-PREPROCESS]>>>"
BANNER_REPLAY_SINGLE = ">>>[NASS-REPLAY-SINGLE]>>>"
BANNER_REFINE = ">>>[NASS-REFINE]>>>"


def orchestrate_fuzz(
        service_name: str,
        device_id: str,
        corpus_dirs: Optional[list[str]] = None,
        fuzz_code: Optional[bool] = False,
        fuzz_parcel: Optional[bool] = False,
        fuzz_data: Optional[bool] = False,
        fuzz_no_deserializers: Optional[bool] = False,
        pid_filter: Optional[bool] = False,
        dump: Optional[bool] = False,
        cov_rate: Optional[bool] = False,
        fuzz_time: Optional[int] = None,
        max_service_restarts: Optional[int] = None,
        max_device_restarts: Optional[int] = None,
        print_function = print) -> str:
    command = f"python3 -u {BASE_DIR}/orchestrate.py \
        -s {service_name} -d {device_id}"
    if pid_filter:
        command += f" --pid_filter"
    if fuzz_time is not None:
        command += f" -t {int(fuzz_time)}"
    if corpus_dirs is not None:
        for corpus_dir in corpus_dirs:
            command += f" -c {corpus_dir}"
    if max_service_restarts is not None:
        command += f" --max_service_restarts {max_service_restarts}"
    if max_device_restarts is not None:
        command += f" --max_device_restarts {max_device_restarts}"
    if fuzz_code and fuzz_parcel:
        log.error(
            f'orchestrate_fuzz incorrect usage both fuzz_code and fuzz_parcel are true'
        )
        return None
    if fuzz_code:
        command += f" --fuzz_code"
    if fuzz_parcel:
        command += f" --fuzz_parcel"
    if fuzz_data:
        command += f" --fuzz_data"
    if fuzz_no_deserializers:
        command += f" --fuzz_no_deserializers"
    if dump:
        command += f" --dump"
    if cov_rate:
        command += f" --fuzz_cov_rate" 
    info = {"iteration": 0, "new": 0, "crashes": 0, "output_path": None}
    curr_iter = 0
    log.info(f'{BANNER} {command}')
    print_function(f'{BANNER} {command}')
    for line in exec_cmd(command):
        line = line.strip("\n")
        if f"device {device_id} not connected" in line:
            raise adb.ADBDeviceNotFound
        orch_parse_line(line, info, print_function=print_function)
        if "interrupted by user" in line:
            raise KeyboardInterrupt
        if info["iteration"] > curr_iter+50:
            curr_iter = info["iteration"]
            log.info(f'{BANNER} {service_name} executions: {info["iteration"]}, execs/s: {info["execs_s"]}, seeds: {info["new"]}, crashes: {info["crashes"]}')
            print_function(f'{BANNER} {service_name} executions: {info["iteration"]}, execs/s: {info["execs_s"]}, seeds: {info["new"]}, crashes: {info["crashes"]}')
    return info["output_path"]

def orch_parse_line(line, info, print_function=None):
    #TODO Also parse the time and device borked
    log.debug(f"parsing line: {line}")
    if "output" in line:
        pattern = r"output: (/.+)"
        match = re.search(pattern, line)
        if match:
            output_path = match.group(1)
            if info["output_path"] is None:
                log.debug(f"output path: {output_path}")
                info["output_path"] = output_path 
    if "[LIBFUZZ]" in line:
        pattern = r"\[LIBFUZZ\] #(\d+)"
        match = re.search(pattern, line)
        if match:
            iiter = int(match.group(1))
            info["iteration"] = iiter
            if "NEW" in line:
                p2 = r"corp: (\d+)/"
                m2 = re.search(p2, line)
                if m2:
                    info["new"] = int(m2.group(1))
            p3 = r"exec\/s: (\d+)"
            m3 = re.search(p3, line)
            if m3:
                info["execs_s"] = int(m3.group(1))
    if "Service pid is gone" in line:
        info["crashes"] += 1
        log.debug(f"service crashed!")
        if print_function is not None:
            print_function(f"{BANNER} service crashed!")
    if "service was terminated by orchestrator, waiting for restart" in line:
        if print_function is not None:
            print_function(f"{BANNER} service terminated by fuzzer (to reset dumping)")
    if "==========================" in line:
        log.debug(
            f'fuzzer running iteration:#{info["iteration"]}, new seeds: {info["new"]}'
        )
    if "[ERROR]" in line:
        log.debug('ERROR? ' + line)
        if print_function is not None:
            print_function(f'{BANNER} error: {line}')


def triage(
        service_name: str,
        device_id: str,
        fuzz_out_dir: str,
        print_function: print):
    command = f"python3 -u {BASE_DIR}/triage.py \
            -s {service_name} -d {device_id} \
            -i {fuzz_out_dir}"
    log.info(f"{BANNER_TRIAGE} {command}")
    print_function(f"{BANNER_TRIAGE} {command}")
    for line in exec_cmd(command):
        line = line.strip("\n")
        triage_parse_line(line, print_function)

def triage_parse_line(line, print_function):
    #print_function(f"parsing line: {line}")
    if "replaying crash" in line:
        print_function(line)


def preprocess(
    service_name: str, 
    device_id: str, 
    print_function=print
):
    command = f"python3 -u {BASE_DIR}/preprocess.py \
            -s {service_name} -d {device_id}"
    log.info(f'{BANNER_PREPROC} command')
    print_function(f"{BANNER_PREPROC} {command}")
    for line in exec_cmd(command):
        line = line.strip("\n")
        if f"device {device_id} not connected" in line:
            raise adb.ADBDeviceNotFound
        print_function(f"{BANNER_PREPROC} {line}")


def check_crashing(
    service_name : str, 
    device_id : str,
    input_seed : str,
    print_function = print
    ):
    command = f"python3 -u {BASE_DIR}/replay.py single -s {service_name} \
        -d {device_id} -f {input_seed}" 
    log.info(f'{BANNER_REPLAY_SINGLE} {command}')
    print_function(f'{BANNER_REPLAY_SINGLE} {command}')
    crashed = [False]
    for line in exec_cmd(command):
        line = line.strip("\n")
        parse_check_crashed(line, crashed, print_function=print_function)
    return crashed[0]

def parse_check_crashed(line, crashed, print_function):
    log.debug(f"parsing line: {line}")
    if "Service CRASHED" in line:
        print_function(f'{BANNER_REPLAY_SINGLE} {line}')
        crashed[0] = True
    if "replayed seed" in line:
        print_function(f'{BANNER_REPLAY_SINGLE} {line}')


def refine(
    service_name : str, 
    device_id : str,
    input_dir : str,
    print_function = print
    ):
    command = f"python3 -u {BASE_DIR}/replay.py refine -s {service_name} \
        -d {device_id} -f {input_dir}"
    log.info(f'>>>[REFINE]>>> {command}')
    print_function(f'>>>[REFINE]>>> {command}')
    for line in exec_cmd(command):
        line = line.strip("\n")
        parse_refine_line(line, print_function=print_function)
    refined_dir = os.path.join(input_dir, "phase_2_seeds")
    if not os.path.exists(refined_dir):
        raise NoRefineDir(f'{refined_dir} does not exist')
    return refined_dir

def parse_refine_line(line, print_function):
    log.debug(f"parsing line: {line}")
    if "replayed seed" in line:
        log.debug(line)
        print_function(f'{BANNER_REFINE} {line}')
    if "assocClass" in line:
        log.debug(line)
        print_function(f'{BANNER_REFINE} {line}')


def exec_cmd(command):
    log.info(f"executing {command}")
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,  # If you want to handle the output as strings rather than bytes
        bufsize=1,  # Line buffered
        universal_newlines=True,
        shell=True,
        encoding="utf-8",
        errors="replace"
    )
    for stdout_line in iter(process.stdout.readline, ""):
        yield stdout_line
    return_code = process.wait()
    for stderr_line in iter(process.stderr.readline, ""):
        yield stderr_line
