import os
import sys
import json
"""
analyze the output of a fuzzing run
"""

def print_info(path):
    data = json.loads(open(path).read())
    for s, out_paths in data.items():
        crashes = []
        seeds = []
        for o in out_paths:
            crashes += [f for f in os.listdir(o) if f.startswith("crash-")]
            seeds += [
                f for f in os.listdir(os.path.join(o, "data")) 
                if not f.endswith(".rng")
            ]
        print(f'{s}: {len(seeds)} seeds, {len(crashes)} crashes')



if len(sys.argv) < 2:
    print("give the path to the fans run_out/*.json")
    exit(0)

inp_path = sys.argv[1]

print_info(inp_path)