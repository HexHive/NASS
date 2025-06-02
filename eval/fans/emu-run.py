import threading
import frida
import argparse
import os
import logging
import traceback
import sys
from datetime import datetime
import time
import re
import json
import tempfile
import subprocess
import threading
import queue

q = queue.Queue()
lock = threading.Lock()

BASE_DIR: str = os.path.dirname(__file__)
REPO_BASE = os.path.join(BASE_DIR, "..", "..")
FANS_FUZZ: str = os.path.join(REPO_BASE, "fans")
NASS_FUZZ: str = os.path.join(REPO_BASE, "fuzz")
sys.path.append(os.path.join(REPO_BASE))
    
CAMPAIGN_OUT_DIR = os.path.join(BASE_DIR, "run_out")

import adb
from config import (
        PAIN, 
        FANS_PIXEL_2_XL, 
        META_TARGET, 
        IS_EMULATOR, 
        AARCH64_EMU_28, 
        AARCH64_EMU_34,
        TARGET_DIR,
        RED,
        NC,
        FANS_EVAL_TIME,
        FANS_EVAL_RUNS
)
import fuzz.nass_api as nass_api 
import fans.fans_api as fans_api
import utils.utils as utils
import emulator.emulator as emulator

if not 'PARALLEL_EMULATORS' in os.environ:                                                                                                  
    print('specify PARALLEL_EMULATORS env variable')
    exit(0)
else:
    PARALLEL_EMULATORS = int(os.environ['PARALLEL_EMULATORS'])

if "CAMPAIGN_RUNTIME" in os.environ:
    CAMPAIGN_TIME = int(os.environ["CAMPAIGN_RUNTIME"])
else:
    CAMPAIGN_TIME = FANS_EVAL_TIME 

if "CAMPAIGN_RUNS" in os.environ:
    CAMPAIGN_RUNS = int(os.environ["CAMPAIGN_RUNS"])
else:
    CAMPAIGN_RUNS = FANS_EVAL_RUNS

os.system(f'mkdir -p {os.path.join(BASE_DIR, "log")}')

if len(logging.root.handlers) == 0:
    logging.basicConfig(
    filename=os.path.join(BASE_DIR, "log", "campaign-run.log"),
    encoding="utf-8",
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(filename)s.%(funcName)s %(message)s",
    force=True,
)

log = logging.getLogger(__name__)

"""
run fuzzers on targets for X hours
"""

job_NASS_FUZZ = "NASS_FUZZ"
job_FANS_FUZZ = "FANS_FUZZ"
job_FANS_NOVARMAP_FUZZ = "FANS_NOVARMAP_FUZZ"
job_NASS_NODESER_FUZZ = "NASS_NODESER_FUZZ"
job_NASS_DRCOV = "NASS_DRCOV"
job_NASS_NOPREPROC_DRCOV = "NASS_NOPREPROC_DRCOV"
job_NASS_NODESER_DRCOV = "NASS_NODESER_DRCOV"
job_FANS_DRCOV = "FANS_DRCOV"
job_FANS_NOVARMAP_DRCOV = "FANS_NOVARMAP_DRCOV"

class Job:
    def __init__(self, name, service, path=None):
        self.name = name
        self.service = service
        self.path = path

class Worker:
    def __init__(self, device_id, color, meta_device_id, out_path):
        self.device_id = device_id
        self.color = color
        self.meta_device_id = meta_device_id
        self.out_path = out_path
        self.log_file = os.path.join(BASE_DIR, 'log', f'worker_{device_id}.log')
        if os.path.exists(self.log_file):
            os.system(f'rm {self.log_file}')
        os.system(f'touch {self.log_file}')

    def run(self):
        while True:
            if q.empty():
                self.thread_print("done")
                return
            j = q.get()
            self.process(j)

    def process(self, job: Job):
        if job.name == job_NASS_FUZZ:
            self.nass_fuzz(job)
        elif job.name == job_NASS_NODESER_FUZZ:
            self.nass_nodeser_fuzz(job)
        elif job.name == job_FANS_FUZZ:
            self.fans_fuzz(job)
        elif job.name == job_FANS_NOVARMAP_FUZZ:
            self.fans_novarmap_fuzz(job)
        elif job.name == job_NASS_DRCOV or job.name == job_NASS_NODESER_DRCOV:
            self.nass_drcov(job)
        elif job.name == job_FANS_DRCOV or job.name == job_FANS_NOVARMAP_DRCOV:
            self.fans_drcov(job)

    def thread_print(self, line):
        print(f'{self.color}[{self.device_id}]{line}{NC}')
        open(self.log_file, 'a+').write(f'[{self.device_id}]{line}\n')

    def nass_fuzz(self, job: Job):
        emulator.full_reset(self.device_id)
        service = job.service
        self.thread_print(f'starting nass fuzzing for {service}')
        final_seed_dir = os.path.join(
            NASS_FUZZ,
            "..",
            "targets",
            self.meta_device_id,
            service,
            "preprocess",
            "final"
        )
        output_path = nass_api.orchestrate_fuzz(
            service_name = service,
            device_id = self.device_id,
            corpus_dirs = [final_seed_dir],
            fuzz_data = True,
            fuzz_time = CAMPAIGN_TIME,
            print_function = self.thread_print,
            dump="DUMPSEEDS"in os.environ
        )
        self.thread_print(f'finished nass fuzzing for {service}')
        q.put(Job(job_NASS_DRCOV, service, output_path))

    def nass_nopreproc_fuzz(self, job: Job):
        emulator.full_reset(self.device_id)
        service = job.service
        self.thread_print(f'starting nass no preproc fuzzing for {service}')
        output_path = nass_api.orchestrate_fuzz(
            service_name = service,
            device_id = self.device_id,
            fuzz_time = CAMPAIGN_TIME,
            print_function = self.thread_print
        )
        self.thread_print(f'finished nass nopreproc fuzzing for {service}')
        q.put(Job(job_NASS_NOPREPROC_DRCOV, service, output_path)) 

    def nass_nodeser_fuzz(self, job: Job):
        emulator.full_reset(self.device_id)
        service = job.service
        self.thread_print(f'starting nass nodeser fuzzing for {service}')
        output_path = nass_api.orchestrate_fuzz(
            service_name = service,
            device_id = self.device_id,
            fuzz_no_deserializers=True,
            fuzz_time = CAMPAIGN_TIME,
            print_function = self.thread_print
        )
        self.thread_print(f'finished nass nodeser fuzzing for {service}')
        q.put(Job(job_NASS_NODESER_DRCOV, service, output_path)) 

    def fans_fuzz(self, job: Job):
        emulator.full_reset(self.device_id)
        service = job.service
        self.thread_print(f'starting fans fuzzing for {service}')
        output_path = fans_api.orchestrate_fuzz(
            service_name = service,
            device_id = self.device_id,
            fuzz_time = CAMPAIGN_TIME,
            print_function = self.thread_print
        )
        self.thread_print(f'finished fans fuzzing for {service}')
        q.put(Job(job_FANS_DRCOV, service, output_path)) 

    def fans_novarmap_fuzz(self, job: Job):
        emulator.full_reset(self.device_id)
        service = job.service
        self.thread_print(f'starting fans_novarmap fuzzing for {service}')
        output_path = fans_api.orchestrate_fuzz(
            service_name = service,
            device_id = self.device_id,
            fuzz_time = CAMPAIGN_TIME,
            novarmap= True,
            print_function = self.thread_print
        )
        self.thread_print(f'finished fans fuzzing for {service}')
        q.put(Job(job_FANS_NOVARMAP_DRCOV, service, output_path))  

    def nass_drcov(self, job: Job):
        emulator.full_reset(self.device_id)
        service = job.service
        self.thread_print(f'starting nass drcov for {service}')
        out_path = job.path
        fans_api.replay(
            service_name = service,
            device_id = self.device_id,
            input_dir = out_path,
            fuzzer = "nass",
            print_function = self.thread_print
        )
        self.thread_print(f'finished nass drcov for {service}')
        lock.acquire()
        cur = json.load(open(self.out_path, 'r'))
        if job.name == job_NASS_DRCOV:
            out_name = 'nass'
        elif job.name == job_NASS_NOPREPROC_DRCOV:
            out_name = 'nass_nopreproc'
        elif job.name == job_NASS_NODESER_DRCOV:
            out_name = 'nass_nodeser'
        elif job.name == job_NASS_SEED_DRCOV:
            out_name = 'nass_seeded'
        if out_name not in cur["services"][service]:
            cur["services"][service][out_name] = [out_path]
        else:
            cur["services"][service][out_name].append(out_path) 
        open(self.out_path,'w').write(json.dumps(cur))
        lock.release()
        self.thread_print(f'status for service {cur["services"][service]}')

    def fans_drcov(self, job: Job):
        emulator.full_reset(self.device_id)
        service = job.service
        self.thread_print(f'starting fans drcov for {service}')
        out_path = job.path
        fans_api.replay(
            service_name = service,
            device_id = self.device_id,
            input_dir = out_path,
            fuzzer = "fans",
            print_function = self.thread_print
        )
        self.thread_print(f'finished fans drcov for {service}')
        lock.acquire()
        if job.name == job_FANS_DRCOV:
            out_name = 'fans'
        elif job.name == job_FANS_NOVARMAP_DRCOV:
            out_name = 'fans_novarmap'
        cur = json.load(open(self.out_path, 'r'))
        if out_name not in cur["services"][service]:
            cur["services"][service][out_name] = [out_path] 
        else:
            cur["services"][service][out_name].append(out_path)
        open(self.out_path,'w').write(json.dumps(cur))
        lock.release()
        self.thread_print(f'status for service {cur["services"][service]}')


def start_worker(worker: Worker):
    worker.run()

if __name__ == "__main__":

    if not os.path.exists(CAMPAIGN_OUT_DIR):
        os.system(f'mkdir -p {CAMPAIGN_OUT_DIR}')

    if len(sys.argv) > 1:
        run_name = sys.argv[1]
    else:
        run_name = ""
    
    if IS_EMULATOR:
        devices = []
        start_port = 5554
        if "CAMPAIGN_NREMU" in os.environ:
            nr_emus = int(os.environ["CAMPAIGN_NREMU"])
        else:
            nr_emus = PARALLEL_EMULATORS
        for i in range(0, nr_emus):
            devices.append(f'emulator-{start_port + 2*i}')
    else:
        print(f'{RED} not running this script for real devices..{NC}')
        exit(-1)

    print(f'removing existing dockers')
    d_tmp = adb.get_device_ids()
    for d in d_tmp:
        if d.startswith('emulator-'):
            os.system(f'docker kill docker_{d}')
    time.sleep(5)
    print(f'finished removing dockers')

    if META_TARGET is None:
        print(f'{RED} META_TARGET NEEDS TO BE SET{NC}')
        exit(-1)
    
    if "CAMPAIGN_SERVICES" in os.environ:
        services = open(os.environ["CAMPAIGN_SERVICES"]).read().split("\n")[:-1]
    elif META_TARGET == AARCH64_EMU_28:
        services = open(os.path.join(BASE_DIR, "./fans_eval_services.txt")).read().split("\n")[:-1]
    else:
        print(f'{RED} Unknown target!{NC}')
        exit(-1)

    out_path = os.path.join(
        CAMPAIGN_OUT_DIR,
        f'{run_name}_out.json'
    )

    out = {
        "time": CAMPAIGN_TIME,
        "services": {}
    }
    print(f'out path: {out_path}')

    services_todo = []
    for s in services:
        preproc_path = os.path.join(TARGET_DIR, META_TARGET, s, "preprocess")
        preproc_final = os.path.join(preproc_path, "final")
        if not os.path.exists(preproc_final):
            print(f'no preprocesing for servcie: {s}, skipping..')
            continue
        services_todo.append(s)

    for i, s in enumerate(services_todo):
        for _ in range(0, CAMPAIGN_RUNS):
            if META_TARGET == AARCH64_EMU_28 and not "NO_FANS" in os.environ:
                q.put(Job(job_FANS_FUZZ, s))
            if not "NO_NASS" in os.environ:
                q.put(Job(job_NASS_FUZZ, s))
            if "NASS_ABLATION" in os.environ:
                q.put(Job(job_NASS_NODESER_FUZZ, s))
            if "FANS_NOVARMAP" in os.environ:
                q.put(Job(job_FANS_NOVARMAP_FUZZ, s))
        out["services"][s] = {}

    open(out_path, 'w+').write(json.dumps(out))
    print(f'fuzzing {CAMPAIGN_RUNS} times for {CAMPAIGN_TIME} s')
    print(f'working for {len(services_todo)}')

    threads = []

    for i,d in enumerate(devices):
        worker = Worker(
            d, utils.worker_color(i, len(devices)), META_TARGET, out_path
        )
        threads.append(threading.Thread(target=start_worker, args=[worker,]))

    for t in threads:
        t.start()
        time.sleep(5)

    for t in threads:
        t.join()

    print(f'removing existing dockers')
    d_tmp = adb.get_device_ids()
    for d in d_tmp:
        if d.startswith('emulator-'):
            os.system(f'docker kill docker_{d}')
    time.sleep(5)
    print(f'finished removing dockers')

    
