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
print('[GHIDRA][fnameoff_from_off] analyzing ' + binaryPath)

base_address = program.getImageBase().getUnsignedOffset()

decompinterface = DecompInterface()
decompinterface.openProgram(program)
functions = program.getFunctionManager().getFunctions(True)
addressFactory = currentProgram.getAddressFactory()
func_dict = {}
for function in list(functions):
    func_dict[str(function)] = function

def getLastFunctionAddress(func, funcManager):
    # find the last function address
    entry = func.getEntryPoint()
    funcs = funcManager.getFunctions(entry, True)
    i = 0
    for func in funcs:
        print(func)
        i += 1
        if i == 2:
            break
    last_addr = func.getEntryPoint()
    return last_addr

def get_non_thunked(func):
    if not func.isThunk():
        return func
    return func.getThunkedFunction(True)

def actual_get_non_thunked(func):
    called = list(func.getCalledFunctions(monitor))
    print('[GHIDRA] thunk outgoing calls', called, len(called))
    if len(called) > 1:
        print('[GHIDRA] cursed non_thunk detection failed...')
        return func 
    return called[0]

# inp: 
inp_path = args.input
out_path = args.output

inp = json.load(open(inp_path))

out = {}

ghidra_offset = int(currentProgram.getImageBase().getOffset())

for offset in inp:
    offset_adj = int(offset + ghidra_offset)
    print('[GHIDRA][DEBUG] offset_adj: ' + hex(offset_adj))
    addr = addressFactory.getAddress(hex(offset_adj)) 
    func_found = fmanager.getFunctionContaining(addr)
    print('[GHIDRA] function found (thunk?)', func_found, func_found.getEntryPoint())
    last_addr_ghidra = getLastFunctionAddress(func_found, program.getFunctionManager())
    """
    func_found = get_non_thunked(func_found)
    print('[GHIDRA] function found (still thunk?)', func_found, func_found.getEntryPoint())
    last_addr_ghidra = getLastFunctionAddress(func_found, program.getFunctionManager())
    if(int(last_addr_ghidra.getOffset()) - int(func_found.getEntryPoint().getOffset())) < 0x20:
        # still looking at a thunk
        func_found = actual_get_non_thunked(func_found)
        func_found = get_non_thunked(func_found)
        last_addr_ghidra = getLastFunctionAddress(func_found, program.getFunctionManager()) 
        print('[GHIDRA] function found (finally non-thunk?)', func_found, func_found.getEntryPoint())
    """
    print('[GHIDRA][fnameoff_from_off] found function at ' + str(hex(offset)) + ':' + func_found.getName() + ':' + hex(func_found.getEntryPoint().getOffset()-ghidra_offset) + '-' + hex(last_addr_ghidra.getOffset()-ghidra_offset))
    out[int(offset)] = {"fname": func_found.getName(), "f_off": int(func_found.getEntryPoint().getOffset()-ghidra_offset), 'f_end': int(last_addr_ghidra.getOffset()-ghidra_offset)}

open(out_path, "w+").write(json.dumps(out))
exit(0)
