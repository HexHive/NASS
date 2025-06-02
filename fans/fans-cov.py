import os
import argparse
import json
import subprocess
import time

BASE_DIR: str = os.path.dirname(__file__)
"""
run coverage extraction over all output paths
"""

def get_seeds_nr(out_path, fuzzer):
    if fuzzer == "fans":
        files = os.listdir(os.path.join(out_path, "data"))
        return len([f for f in files if not f.endswith(".rng")])
    elif fuzzer == "nass":
        return len(os.listdir(os.path.join(out_path, "data")))
    else:
        print("unknown fuzzer..")
        exit(-1)

def do_replay(service, device, fuzz_out, fuzzer):
        print(f"start fuzzing: {service}")
        command = f"python3 -u {BASE_DIR}/fans-replay.py {fuzzer} -s {service} -d {device} -f {fuzz_out}"
        print(f"executing {command}")
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

def run_replay(service, device_id, out_path, fuzzer):
    replayed_seeds = 0
    seeds_to_replay = get_seeds_nr(out_path, fuzzer)
    start = time.time()
    for line in do_replay(service, device_id, out_path, fuzzer):
        line = line.strip("\n")
        print(f'replay line: {line}')
        if 'replayed seed' in line:
            replayed_seeds += 1
        print(f'[*] COV [{replayed_seeds}/{seeds_to_replay}] {time.time()- start}')

def extract_coverage(device_id, run_json):
    run_out = json.load(open(run_json))
    json_name = os.path.basename(run_json)
    fuzzer = None
    if json_name.startswith("fans-"):
        fuzzer = "fans"
    elif json_name.startswith("nass-"):
        fuzzer = "nass"
    else:
        print(f'unknown run_out fuzzer...')
        exit(-1)
    for s, out_paths in run_out.items():
        if len(out_paths) == 0:
            print(f'{s} {run_json} has no fuzzing output path...')
            continue
        elif len(out_paths) != 1:
            print(f'{s} {run_json} wtf more than one output path: {out_paths}')
        for out_path in out_paths: 
            drcov_dir = os.path.join(out_path, "drcov")
            if os.path.exists(drcov_dir) and len(os.listdir(drcov_dir)) > 0:
                print(f'already finished extreacing coverage for {s}')
                continue
            # sanity check
            data_dir = os.path.join(out_path, "data")
            if not os.path.exists(data_dir) or len(os.listdir(data_dir))==0:
                print(f'{s} {out_path}, empty or nonexistent data directory...')
                continue
            print(f'Extracting coverage for {s} on {device_id}, {out_path}')
            run_replay(s, device_id, out_path, fuzzer)


if __name__ == "__main__":

    ############################################################################
    # set up argument parser
    ############################################################################

    parser = argparse.ArgumentParser(
        description=f"Replay seeds against a service to refine seeds or extract \
        drcov coverage"
    )
    
    parser.add_argument(
        "-d", "--device", type=str, required=True, help="device to test"
    )
    parser.add_argument(
        "-r",
        "--run_json",
        type=str,
        required=True,
        help="path to output run json",
    )
    args = parser.parse_args()

    extract_coverage(args.device, args.run_json)
