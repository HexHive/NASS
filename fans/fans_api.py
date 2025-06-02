import logging 
import re
import subprocess
from typing import Optional
import os

BASE_DIR: str = os.path.dirname(__file__)

log = logging.getLogger(__name__)

BANNER_ORCH = ">>>[FANS-ORCH]>>>"
BANNER_REFINE = ">>>[FANS-REFINE]>>>"


def orchestrate_fuzz(
        service_name: str,
        device_id: str,
        fuzz_time: Optional[int] = None, 
        novarmap: Optional[bool] = False,
        print_function = print
    ) -> str:
    command = f"python3 -u {BASE_DIR}/fans-orchestrate.py \
        -s {service_name} -d {device_id}"
    if fuzz_time is not None:
        command += f" -t {int(fuzz_time)}"
    if novarmap:
        command += f" --no_varmap"
    info = {"iteration": 0, "new": 0, "crashes": 0, "output_path": None}
    curr_iter = 0
    log.info(f'{BANNER_ORCH} {command}')
    print_function(f'{BANNER_ORCH} {command}')
    for line in exec_cmd(command):
        line = line.strip("\n")
        parse_line_orch(line, info)
        if "interrupted by user" in line:
            raise KeyboardInterrupt
        if info["iteration"] > curr_iter+50:
            curr_iter = info["iteration"]
            log.info(f'{BANNER_ORCH} {service_name} executions: {info["iteration"]}, seeds: {info["new"]}, crashes: {info["crashes"]}')
            print_function(f'{BANNER_ORCH} {service_name} executions: {info["iteration"]}, seeds: {info["new"]}, crashes: {info["crashes"]}')
    return info["output_path"]

def parse_line_orch(line, info):
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
    if "NEW nr seeds" in line:
        pattern = r"nr seeds: (\d+)"
        match = re.search(pattern, line)
        if match:
            info["new"] = int(match.group(1))
    if "SERVICE CRASHED" in line:
        info["crashes"] += 1
    if "Fuzzer iteration" in line:
        pattern = r"Fuzzer iteration (\d+)"
        match = re.search(pattern, line)
        if match:
            info["iteration"] = int(match.group(1))


def replay(
    service_name : str,
    device_id : str,
    input_dir : str,
    fuzzer: str,
    print_function = print
    ):
    command = f"python3 -u {BASE_DIR}/fans-replay.py {fuzzer} -s {service_name} \
        -d {device_id} -f {input_dir}"
    log.info(f'{BANNER_REFINE} {command}')
    print_function(f'{BANNER_REFINE} {command}')
    for line in exec_cmd(command):
        line = line.strip("\n")
        parse_refine_line(line, print_function=print_function)

def parse_refine_line(line, print_function):
    log.debug(f"parsing line: {line}")
    if "replayed seed" in line:
        print_function(f'{BANNER_REFINE} {line}')
    if "covered libraries" in line:
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
