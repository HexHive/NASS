import logging 
import subprocess
import os

BASE_DIR: str = os.path.dirname(__file__)

log = logging.getLogger(__name__)
BANNER = '>>>[REFINE]>>>'

def replay(
    service_name : str, 
    device_id : str,
    input_dir : str,
    fuzzer: str,
    print_function = print
    ):
    command = f"python3 {BASE_DIR}/fans-replay.py {fuzzer} -s {service_name} \
        -d {device_id} -f {input_dir}"
    log.info(f'{BANNER} {command}')
    print_function(f'{BANNER} {command}')
    for line in exec_cmd(command):
        line = line.strip("\n")
        parse_refine_line(line, print_function=print_function)

def parse_refine_line(line, print_function):
    log.debug(f"parsing line: {line}")
    if "replayed seed" in line:
        print_function(f'{BANNER} {line}')
    if "covered libraries" in line:
        print_function(f'{BANNER} {line}')

def exec_cmd(command):
    log.info(command)
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
