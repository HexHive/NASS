# use it with:
# analyzeHeadless $(mktemp -d) HeadlessAnalysis -overwrite -import <file> -scriptPath $(pwd) -postscript ghidra_dump_native_calls.py
import re
import os
from argparse import ArgumentParser
import json
import subprocess

from  ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.address import Address
from ghidra.program.model.address import DefaultAddressFactory 
#from ghidra.program.model.listing import getCalledFunctions, getCallingFunctions


def exit_not_found(output_path, reason):
    open(output_path, "w+").write(json.dumps({"result": "failed", "status": reason}))
    exit(-1)

def exit_found(output_path, entry_addr):
    open(output_path, "w+").write(json.dumps({"result": "success", "invoke": hex(entry_addr)}))
    exit(0)

arg_parser = ArgumentParser(description="find TA_InvokeCommandEntryPoint", prog='script',
                            prefix_chars='+')
arg_parser.add_argument('+o', '++output', required=True, help='Output file for JSON')
arg_parser.add_argument('+t', '++input', required=True, help='which tee/vendor combination are we analyzing')
args = arg_parser.parse_args(args=getScriptArgs())


program = currentProgram
memory = program.getMemory()
addressFactory = currentProgram.getAddressFactory()
binaryPath = currentProgram.getExecutablePath()
listing = currentProgram.getListing()
fmanager = currentProgram.getFunctionManager()
filename = os.path.basename(binaryPath)
print('[GHIDRA][off_from_fname] analyzing ' +binaryPath)

base_address = program.getImageBase().getUnsignedOffset()

decompinterface = DecompInterface()
decompinterface.openProgram(program)
functions = program.getFunctionManager().getFunctions(True)
addressFactory = currentProgram.getAddressFactory()


def getLastFunctionAddress(func, funcManager):
    # find the last function address
    entry = func.getEntryPoint()
    funcs = funcManager.getFunctions(entry, True)
    i = 0
    for func in funcs:
        print("[*] getFunctionLastAddress: " + str(func))
        i += 1
        if i == 2:
            break
    last_addr = func.getEntryPoint()
    print("[*] funcgetLastAddress, last_addr found: " + str(last_addr) + " offset: " + str(last_addr.getOffset()-ghidra_offset))
    return last_addr

def get_non_thunked(func):
    if not func.isThunk():
        return func
    return func.getThunkedFunction(True)

func_dict = {}
for function in list(functions):
    func_dict[str(function)] = function

# inp: 
fname = args.input
out_path = args.output

out = {}
ghidra_offset = int(currentProgram.getImageBase().getOffset())
print("[*] baseaddress?!? "+ str(ghidra_offset))

def is_same_function(ghidra_fname, fname_inp):
    #print("[GHIDRA][is_same_function]: are these the same functions: "+ ghidra_fname + ", " + fname_inp)
    return ghidra_fname == fname_inp

found = False
for fname_ghidra, f in func_dict.items():
    if is_same_function(fname_ghidra, fname):
        print("found", fname, f.isThunk(), f.getEntryPoint().getOffset(), f.getThunkedFunction())
        continue
        f = get_non_thunked(f)
        last_addr_ghidra = getLastFunctionAddress(f, program.getFunctionManager())
        out[fname] = {'fname': fname_ghidra, 'f_off': int(f.getEntryPoint().getOffset()-ghidra_offset), 'f_end': int(last_addr_ghidra.getOffset()-ghidra_offset)}
        print('[GHIDRA][off_from_fname] found function offset for ' + fname +':' + out[fname]["fname"] + ':' + hex(f.getEntryPoint().getOffset()) + '-' + hex(last_addr_ghidra.getOffset()-ghidra_offset))
        found = True
        break
if not found:
    out[fname] = None



open(out_path, "w+").write(json.dumps(out))
exit(0)
