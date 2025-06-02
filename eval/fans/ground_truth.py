import os
import json

"""
calculates command id stats
"""

#standard_commands = ["1599295570", "1598311760", "1598968902", "1598246212"]
standard_commands = ["1599295570", "1598311760", "1598968902"]
services = ["android.security.keystore", "android.service.gatekeeper.IGateKeeperService", "perfprofd", "stats", "wificond", "SurfaceFlinger", "netd", "installd",   "vold",  "gpu", "media.metrics", "storaged", "thermalservice", "incident"]

ground_truth = {}
ground_truth_cmds = {}
captured = {}
nass = {}


if __name__ == "__main__":
    captured_json = json.load(open(f'ipc_capture/final.json'))
    for s in services:
        if s in captured_json:
            captured[s] = len([cmd_id for cmd_id in captured_json[s] if cmd_id not in standard_commands])
        else:
            captured[s] = 0
        ground_truth[s] = len([cmd_id for cmd_id in json.load(open(f'ground_truth/aarch64emu28/{s}.json')).keys() if cmd_id not in standard_commands])
        ground_truth_cmds[s] = [cmd_id for cmd_id in json.load(open(f'ground_truth/aarch64emu28/{s}.json')).keys() if cmd_id not in standard_commands]
        non_crashing_cmds = [cmd_id for cmd_id in os.listdir(os.path.join(f'nass_extracted/aarch64emu28/{s}/preprocess/final/')) if (cmd_id not in standard_commands and cmd_id in ground_truth_cmds[s])]
        nass[s] = len(non_crashing_cmds)
        if os.path.exists(os.path.join(f'nass_extracted/targets/aarch64emu28/{s}/preprocess/crashing/')):
            nass[s] += len([cmd_id for cmd_id in os.listdir(os.path.join(f'nass_extracted/targets/aarch64emu28/{s}/preprocess/crashing/')) if (cmd_id not in standard_commands and cmd_id in ground_truth_cmds[s]) and cmd_id not in non_crashing_cmds])
        
    print(f'service\t\t\t\t\t\t#RPC functions\t#NASS Disc. RPC. Funcs.\t#Capt. RPC Funcs.')
    for s in services:
        if len(s) == 3:
            nr_tabs = len(s)//4+2
        elif len(s) < 10:
            nr_tabs = len(s)//4+1
        elif s == "android.service.gatekeeper.IGateKeeperService" :
            nr_tabs = 7
        elif len(s) > 24:
            nr_tabs = len(s)//4-1
        
        else:
            nr_tabs = len(s)//4
        print(f'{s}{(8-nr_tabs)*"\t"}{ground_truth[s]}\t\t{nass[s]} {nass[s]*100//ground_truth[s]}%\t\t\t{captured[s]} {captured[s]*100//ground_truth[s]}%')
    sum_gt = sum(c for b,c in ground_truth.items())
    sum_nass = sum(c for b,c in nass.items())
    sum_capt = sum(c for b,c in captured.items())
    print(f'overall\t\t\t\t\t\t{sum_gt}\t\t{sum_nass} {sum_nass*100//sum_gt}%\t\t\t{sum_capt} {sum_capt*100//sum_gt}%')


