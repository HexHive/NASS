import subprocess
import time
import argparse
import sys
import os
import threading
import queue

q = queue.Queue()

BASE_DIR = os.path.dirname(__file__)
REPO_BASE = os.path.join(BASE_DIR, "..", "..")
sys.path.append(REPO_BASE)

from config import IS_EMULATOR, NC, META_TARGET, AARCH64_EMU_28, AARCH64_EMU_34
import utils.utils as utils

TARGETS = os.path.join(REPO_BASE, "targets")


if not 'PARALLEL_EMULATORS' in os.environ:
    print('specify PARALLEL_EMULATORS env variable')
    exit(0)
else:
    PARALLEL_EMULATORS = int(os.environ['PARALLEL_EMULATORS'])

def worker(d, color):
    while True:
        if q.empty():
            print(f"{color}done{NC}")
            return
        s = q.get()
        run_preproc(s, d, color)

def exec_cmd(command):
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,  # If you want to handle the output as strings rather than bytes
        bufsize=1,  # Line buffered
        universal_newlines=True,
        shell=True,
    )
    for stdout_line in iter(process.stdout.readline, ""):
        yield stdout_line
    return_code = process.wait()
    for stderr_line in iter(process.stderr.readline, ""):
        yield stderr_line

def run_preproc(s, d, color=NC):
    if s == "" or s == "\n":
        return 
    s = s.strip("\n")
    for d_test in devices:
        if os.path.exists(f'{REPO_BASE}/targets/{d_test}/{s}/preprocess/final'):
            print(f'{color}{s} already done skipping{NC}')
            return  
    print(f'{color}[{d}] starting for {s} {NC}')
    for line in exec_cmd(f"python3 -u {REPO_BASE}/fuzz/preprocess.py -s {s} -d {d}"):
        line = line.strip("\n")
        print(f'{color}[{d}]{line}{NC}')
    #subprocess.run(f"python3 {BASE_DIR}/../fuzz/preprocess.py -s {s} -d {d} -i 8 -t 300", shell=True)
    print(f'finsihed {s} on {d}')


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description=f"Dynamically extract the interface of a service"
    )
    parser.add_argument(
        "--reset",
        required=False,
        default=False,
        action="store_true",
        help="if set rerun preprocessing for all services",
    )
    
    args = parser.parse_args()    

    if META_TARGET == AARCH64_EMU_28:
        services = open(os.path.join(BASE_DIR, "./fans_eval_services.txt")).read().split("\n")[:-1]

    services_todo = []
    for s in services:
        preproc_path = os.path.join(TARGETS, META_TARGET, s, "preprocess")
        preproc_final = os.path.join(preproc_path, "final")
        if args.reset:
            os.system(f'rm -rf {preproc_path}')
            services_todo.append(s)
        else:
            if not os.path.exists(preproc_final):
                services_todo.append(s)
                os.system(f'rm -rf {preproc_path}')
            else:
                print(f'already done results at: {preproc_final}')

    if IS_EMULATOR:
        devices = []
        start_port = 5554
        for i in range(0, PARALLEL_EMULATORS):
            devices.append(f'emulator-{start_port + 2*i}')
    else:
        print(f'MUST BE RUN ON EMULATOR!')
        exit(-1)

    for i, s in enumerate(services_todo):
        q.put(s)

    print(f'working for {len(services)}')

    threads = []

    for i,d in enumerate(devices):
        threads.append(threading.Thread(target=worker, args=[d,utils.worker_color(i, len(devices))]))

    for t in threads:
        t.start()
        time.sleep(2)

    for t in threads:
        t.join()


