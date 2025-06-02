import os
import tempfile
import json
import sys
import logging
ghidra_path = os.path.join(os.path.dirname(__file__), "ghidra")

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

#from config import config_path
#analyzeHeadless = json.load(open(config_path))["analyzeHeadless"] @TODO: future work to make whole system portable

"""
ghidra utilities
"""

def get_fnameoff_fromoff(binary, offsets):
    # offsets: [f_off1, f_off2, ...]
    inp_tmp = tempfile.mktemp()
    open(inp_tmp,"w+").write(json.dumps(offsets))
    out_tmp = tempfile.mktemp()
    logging.debug(f'callling ghidra: cd {ghidra_path} && ./run.sh {binary} fnameoff_from_off.py {inp_tmp} {out_tmp}')
    os.system(f'cd {ghidra_path} && ./run.sh {binary} fnameoff_from_off.py {inp_tmp} {out_tmp}')
    out = json.load(open(out_tmp, "r"))
    # out: {inp_offset: {'fname': xx, 'f_off': xx}}
    return out


def get_off_from_fname(binary, fname):
    # inp: fname
    out_tmp = tempfile.mktemp()
    logging.debug(f'calling ghidra: cd {ghidra_path} && ./run.sh {binary} off_from_fname.py {fname} {out_tmp}')
    os.system(f'cd {ghidra_path} && ./run.sh {binary} off_from_fname.py {fname} {out_tmp}')
    out = json.load(open(out_tmp, "r"))
    # out: {fname1: {'fname': xx, 'f_off': xx}}
    return out
