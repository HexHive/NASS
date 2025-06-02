import logging
from collections import defaultdict
import base64
import sys
import os

basepath = os.path.dirname(__file__)
sys.path.append(os.path.join(basepath, ".."))
from service.service import Cmd

log = logging.getLogger(__name__)

import utils.utils as utils

RED = "\033[0;31m"
YELLOW = "\033[0;33m"
GREEN = "\033[0;32m"
NC = "\033[0m"
BLUE = "\033[0;34m"  # Blue
PURPLE = "\033[0;35m"  # Purple
CYAN = "\033[0;36m"  # Cyan


class Arg:
    def __init__(self, argtype, value) -> None:
        self.argtype = argtype
        self.value = value

    def get_db_data(self):
        return base64.b64encode(self.value)

    def get_info(self):
        return ""


class Call:
    def __init__(self, cmd_id, args, user="root") -> None:
        self.cmd_id = cmd_id
        self.args = args
        self.user = user


class CallConfig:
    def __init__(self, calls, sleep, runner_margin) -> None:
        self.calls = calls
        self.sleep = sleep
        self.runner_margin = runner_margin


class NativeFunction:
    def __init__(
        self, entry_addr, last_addr, fname_mangled, fname, bin
    ) -> None:
        self.entry_addr = entry_addr
        self.last_addr = last_addr
        self.fname_mangled = fname_mangled
        self.fname = fname
        self.bin = bin

    def __str__(self) -> str:
        return f"{self.bin}!{self.fname}:{hex(self.entry_addr)}-{hex(self.last_addr)}"

    def __repr__(self) -> str:
        return f"{self.bin}!{self.fname}:{hex(self.entry_addr)}-{hex(self.last_addr)}"

    def __eq__(self, other):
        return (
            self.bin == other.bin
            and self.fname_mangled == other.fname_mangled
            and self.fname == other.fname
            and self.entry_addr == other.entry_addr
            and self.last_addr == other.last_addr
        )

    def __hash__(self):
        return hash(
            f"{self.entry_addr}{self.last_addr}{self.bin}{self.fname_mangled}{self.fname}"
        )


class OnTransactNotFoundError(Exception):
    pass


class onTransactFunction(NativeFunction):
    def __init__(
        self,
        entry_addr,
        last_addr,
        fname_mangled,
        fname,
        bin,
        module,
        interface,
        md5,
        BBinder_path,
    ) -> None:
        super().__init__(entry_addr, last_addr, fname_mangled, fname, bin)
        self.module = module
        self.interface = interface
        self.md5 = md5
        self.BBinder_path = BBinder_path


class BacktraceEntry:
    def __init__(
        self, addr, lib, fname_mangled, fname, f_off, vma_off, valid=True
    ) -> None:
        self.addr = addr
        self.lib = lib
        self.fname_mangled = fname_mangled
        self.fname = fname
        self.f_off = f_off
        self.vma_off = vma_off  # offset from vma region
        self.valid = valid

    def __str__(self) -> str:
        return f"{self.lib}!{self.fname}:{hex(self.f_off)}"

    def __repr__(self) -> str:
        return f"{self.lib}!{self.fname}:{hex(self.f_off)}"

    def __eq__(self, other):
        return (
            self.lib == other.lib
            and self.fname_mangled == other.fname_mangled
            and self.fname == other.fname
            and self.f_off == other.f_off
            and self.addr == other.addr
        )

    def __hash__(self):
        return hash(
            f"{self.addr}{self.lib}{self.fname_mangled}{self.fname}{self.f_off}"
        )


class Backtrace:
    def __init__(self, raw_bt_data, proc_map) -> None:
        self._bt = []
        self.isvalid = True
        self.parse_raw(raw_bt_data, proc_map)

    def parse_raw(self, raw_bt_data, proc_map):
        for bt_entry in raw_bt_data.split(","):
            data = bt_entry.split(" ")
            if len(data) < 2:
                try:
                    # usually just an address
                    addr = int(data[0], 16)
                    self._bt.append(
                        BacktraceEntry(addr, "?", "?", "?", -1, -1, valid=False)
                    )
                finally:
                    continue
            addr = int(data[0], 16)
            vma_off = addr - proc_map.get_vmabyaddr(addr).base
            lib_fname_off = data[1]
            lib = lib_fname_off.split("!")[0]
            fname_off = lib_fname_off.split("!")[-1]
            if "+" not in fname_off:
                # check if we have a NOSYMBOL offset or a symbole name with no offset
                try:
                    f_off = int(
                        fname_off, 16
                    )  # if not of format 0x[0-9a-f]will throw an exception
                    fname_mangled = "NOSYMBOL"
                    fname = "NOSYMBOL"
                except:
                    fname_mangled = fname_off
                    fname = utils.demangle_cpp(fname_mangled)
                    f_off = 0x0
            else:
                fname_mangled = fname_off.split("+")[0]
                fname = utils.demangle_cpp(fname_mangled)
                f_off = int(fname_off.split("+")[-1], 16)
            self._bt.append(
                BacktraceEntry(addr, lib, fname_mangled, fname, f_off, vma_off)
            )

    def findcall_by_name(self, name):
        for i, entry in enumerate(self._bt):
            if entry.fname == name:
                return i
        return None

    def findcall_by_name_match(self, name):
        for i, entry in enumerate(self._bt):
            if name in entry.fname:
                return i
        return None

    def __getitem__(self, indices):
        if isinstance(indices, tuple):
            print(f"ERROR! cannot index in multiple dimensions {indices}")
            raise Exception
        return self._bt[indices]

    def __str__(self) -> str:
        out = "Backtrace("
        for bt_entry in self._bt:
            out += f"[{bt_entry}]"
        out += ")"
        return out

    def __repr__(self) -> str:
        out = "Backtrace("
        for bt_entry in self._bt:
            out += f"[{bt_entry}]"
        out += ")"
        return out


class Instruction:
    def __init__(self, raw_data) -> None:
        # {"type": "stalker_callout_instruction", "pc": pc, "instr": instr.toString(), "calling_pid": calling_pid}
        self.pc = raw_data["pc"]
        self.instr = raw_data["instr"]

    def __str__(self):
        return f"{self.pc}:{self.instr}"

    def __repr__(self):
        return f"{self.pc}:{self.instr}"


class InstructionTrace:
    def __init__(self, instructions) -> None:
        self.instructions = instructions

    def __hash__(self) -> int:
        all_data = ",".join(str(instr) for instr in self.instructions)
        return hash(all_data)

    def __str__(self):
        all_data = ",".join(str(instr) for instr in self.instructions)
        return f"InstructionTrace({all_data})"

    def __repr__(self):
        all_data = ",".join(str(instr) for instr in self.instructions)
        return f"InstructionTrace({all_data})"

    def __eq__(self, __value: object) -> bool:
        all_data = ",".join(str(instr) for instr in self.instructions)
        all_data_other = ",".join(str(instr) for instr in __value.instructions)
        return all_data == all_data_other


class FridaData:
    def __init__(self, bt, pid) -> None:
        self.bt = bt
        self.pid = pid


class RecvBBinderData(FridaData):
    def __init__(self, raw_data, proc_map):
        super().__init__(
            Backtrace(raw_data["backtrace"], proc_map),
            int(raw_data["calling_pid"]),
        )
        self.onTransact_addr = int(raw_data["onTransact_addr"], 16)
        self.onTransact_type = raw_data["onTransact_module_type"]
        self.interfaceDescriptor = raw_data["InterfaceDescriptor"]
        self.BBinder_path = raw_data[
            "BBinder_path"
        ]  # if multiple libbinders are loaded we need to know the actual one being used

    def __str__(self) -> str:
        return f"RecvBBinderData(pid:{self.pid},onTransact_addr:{self.onTransact_addr},onTransact_type:{self.onTransact_type},InterfaceDescriptor:{self.interfaceDescriptor})"

    def __repr__(self) -> str:
        return f"RecvBBinderData(pid:{self.pid},onTransact_addr:{self.onTransact_addr},onTransact_type:{self.onTransact_type},InterfaceDescriptor:{self.interfaceDescriptor})"


class RecvStalkerData(FridaData):
    def __init__(self, raw_data, proc_map) -> None:
        super().__init__(
            Backtrace(raw_data["backtrace"], proc_map),
            int(raw_data["calling_pid"]),
        )
        self.seen = raw_data["stalker_trace"]  # TODO: fix if needed

    def __str__(self) -> str:
        return f"RecvStalkerData(pid:{self.pid},seen:{self.seen},bt:{self.bt})"

    def __repr__(self) -> str:
        return f"RecvStalkerData(pid:{self.pid},seen:{self.seen},bt:{self.bt})"


class RecvStalkerCallout(FridaData):
    def __init__(self, calling_pid, instructions) -> None:
        super().__init__(None, calling_pid)
        self.trace = InstructionTrace(instructions)

    def __str__(self) -> str:
        return f"RecvStalkerCallout(pid:{self.pid},trace:{self.trace})"

    def __repr__(self) -> str:
        return f"RecvStalkerCallout(pid:{self.pid},trace:{self.trace})"


class CallData:
    def __init__(self, call, pid, stdout, stderr) -> None:
        self.call = call
        self.pid = pid
        self.stdout = stdout
        self.stderr = stderr


def filter_by_pids(
    frida_binder_callbacks: list[FridaData], calls_made: list[CallData]
):
    # filter all RecvHooks by the pid of the caller
    call_pids = set(cd.pid for cd in calls_made)
    log.debug(f"pids of callers: {call_pids}")
    filtered_callbacks = [
        cb for cb in frida_binder_callbacks if cb.pid in call_pids
    ]
    log.debug(f"filtered callbacks by pid: {filtered_callbacks}")
    return filtered_callbacks


def filter_by_bt(frida_binder_callbacks: list[FridaData]):
    # filter all backtraces whose first entry is libbinder or libbinder_ndk
    blacklist_lib = ["libbinder.so", "libbinder_ndk.so"]
    filtered_callbacks = [
        cb for cb in frida_binder_callbacks if cb.bt[0].lib not in blacklist_lib
    ]
    log.debug(f"filtered callbacks by {filtered_callbacks}")
    return filtered_callbacks


def bt_get_last(bt: Backtrace):
    # look for the last entry in the backtrace that is not libbinder or libbinder_ndk
    blacklist_lib = ["libbinder.so", "libbinder_ndk.so"]
    idx_found = None
    for i, bt_entry in enumerate(bt):
        if bt_entry.lib in blacklist_lib:
            idx_found = i - 1
            break
    if idx_found is None:
        log.debug(f"all entries in bt from non-blacklisted libraries: {bt}")
        return bt[-1]
    if idx_found == -1:
        log.debug(f"first entry in bt is in {blacklist_lib}, {bt}")
        return None
    return bt[idx_found]


def get_likely_onTransact(bt: Backtrace):
    # backtrace to an onTransact call has the following structure:
    # onTransact bt entry
    # [optional] messed up entries
    # [optional] libbinder_ndk!??
    # android::BBinder::transact
    # [optional] messed up entries
    # android::IPCThreadState::executeCommand
    onTransact_poss = bt.findcall_by_name_match("onTransact")
    if onTransact_poss is not None:
        return onTransact_poss
    blacklist_lib = ["libbinder.so", "libbinder_ndk.so"]
    ipc_executecmd_idx = bt.findcall_by_name(
        "android::IPCThreadState::executeCommand"
    )
    if ipc_executecmd_idx is None:
        return None
    bbinder_transact_idx = bt.findcall_by_name("android::BBinder::transact")
    if bbinder_transact_idx is None:
        return None
    # if bbinder_transact_idx +1 != ipc_executecmd_idx:
    if bbinder_transact_idx >= ipc_executecmd_idx:
        log.error(
            f"BBInder::transact not after IPCThreadState::executeCommand? BBinder:transcat:idx:{bbinder_transact_idx},ipc:exec:idx:{ipc_executecmd_idx} {bt}"
        )
        return None
    onTransact_candidate = bt[bbinder_transact_idx - 1]
    if onTransact_candidate.lib == "libbinder_ndk.so":
        onTransact_candidate = bt[bbinder_transact_idx - 2]
    search = bbinder_transact_idx - 2
    while not bt[search].valid:
        # little hacky, some backtrace entries are only addresses
        search -= 1
        if search < 0:
            log.error(
                f"unable to find onTransact candidate, no valid backtrace entries... {bt}"
            )
            return None
    onTransact_candidate = bt[search]
    if onTransact_candidate.lib in blacklist_lib:
        log.error(
            f"unable to find onTransact candidate {onTransact_candidate} {bt}"
        )
        return None
    return onTransact_candidate


def find_onTransact(
    service,
    frida_binder_callbacks: list[RecvBBinderData],
    calls_made: list[CallData],
):
    callbacks_filtered = filter_by_pids(
        frida_binder_callbacks, calls_made
    )  # remove extranous calls

    if not callbacks_filtered:
        raise OnTransactNotFoundError("No onTransact found.")

    log.info(
        f"remaining relevant callbacks after filter by pid: {len(callbacks_filtered)}"
    )

    onTransacts = set([cb.onTransact_addr for cb in callbacks_filtered])
    modules = set([cb.onTransact_type for cb in callbacks_filtered])
    descriptors = set([cb.interfaceDescriptor for cb in callbacks_filtered])
    BBinder_path = set([cb.BBinder_path for cb in callbacks_filtered])

    log.info(
        f"possible onTransact addresses: {onTransacts}, modules: {modules}, InterfaceDescriptor: {descriptors}"
    )

    if len(onTransacts) > 1:
        log.error(
            f"more than one onTransact addresses extracted... {onTransacts}"
        )
        print(f"more than one onTransact addresses extracted... {onTransacts}")
        return None

    if len(modules) > 1:
        log.error(f"more than one onTransact modules... {modules}")
        print(f"more than one onTransact modules... {modules}")
        return None

    if len(descriptors) > 1:
        log.error(f"more than one interface descriptor: {descriptors}")
        print(f"more than one interface descriptor: {descriptors}")
        return None

    if len(BBinder_path) > 1:
        log.error(f"more than one BBinder path... {BBinder_path}")
        print(f"more than one BBinder path... {BBinder_path}")
        return None

    onTransact_addr = list(onTransacts)[0]
    onTransact_module = list(modules)[0]
    onTransact_interface = list(descriptors)[0]
    onTransact_BBinder_path = list(BBinder_path)[0]

    binary = service.proc_map.get_vmabyaddr(onTransact_addr).vma_name
    local_binary_path = service.download_binary(binary)
    bin_md5 = utils.get_md5(local_binary_path)
    onTransact_addr_off = service.proc_map.get_vmaaddroff(onTransact_addr)

    if "libandroid_runtime.so" in onTransact_module:
        service.is_native = False
        # it's a Java service no need to look at this function
        fname_found = f"FUN_00{hex(0x100000+onTransact_addr_off)[2:]}"
        offset_found = onTransact_addr_off
        last_addr_found = -1
    else:
        service.is_native = True
        # TODO: there are rewritten libraries?? fuck it just use the address
        fname_found = f"FUN_00{hex(0x100000+onTransact_addr_off)[2:]}"
        offset_found = onTransact_addr_off
        last_addr_found = -1
        """
        ghidra_res = ghidra.get_fnameoff_fromoff(local_binary_path, [onTransact_addr_off])
        res_dict = ghidra_res[str(onTransact_addr_off)]
        ghidra_fname = res_dict["fname"]
        ghidra_offset = res_dict["f_off"]
        ghidra_last = res_dict["f_end"]
        log.debug(f'ghidra result for {binary}:{hex(int(onTransact_addr_off))} => {ghidra_fname}:{hex(ghidra_offset)}')
        fname_found = ghidra_fname 
        offset_found = ghidra_offset 
        last_addr_found = ghidra_last 
        """
    log.info(
        f"found onTransact function in {binary}!{fname_found} offset:{hex(offset_found)}-{hex(last_addr_found)}"
    )

    return (
        onTransactFunction(
            offset_found,
            last_addr_found,
            fname_found,
            fname_found,
            binary,
            onTransact_module,
            onTransact_interface,
            bin_md5,
            onTransact_BBinder_path,
        ),
        local_binary_path,
    )


def stalker_callout_groupbypid(frida_stalker_callouts):
    pid2instructions = defaultdict(
        list
    )  # @TODO: what happens if I receive callouts out of order?
    for payload in frida_stalker_callouts:
        # {"type": "stalker_callout_instruction", "pc": pc, "instr": instr.toString(), "calling_pid": calling_pid}
        pid = payload["calling_pid"]
        instr = Instruction(payload)
        pid2instructions[pid].append(instr)
    out = []
    for pid, instructions in pid2instructions.items():
        out.append(RecvStalkerCallout(pid, instructions))
    return out


def need_enum_cmd_ids(prev_svc, ignore_cache):
    if ignore_cache:
        return True
    elif prev_svc is None:
        print(f"ERROR: prev_svc when enumerating cmd ids cannot be None!!")
        raise Exception
    elif prev_svc is not None and not prev_svc.cmd_ids_iterated():
        # service exists but no cmd id iteration was yet done
        return True
    else:
        return False


def find_cmd_ids(
    service, frida_stalker_callouts: list, calls_made: list[CallData]
):
    frida_stalker_callouts = stalker_callout_groupbypid(frida_stalker_callouts)
    callbacks_filtered = filter_by_pids(
        frida_stalker_callouts, calls_made
    )  # remove extranous calls
    pid2cb = defaultdict(list)
    cmdid2calls = defaultdict(list)
    instrtr2cmdid = defaultdict(list)
    for cb in callbacks_filtered:
        pid2cb[cb.pid].append(cb)
    for call in calls_made:
        cmdid2calls[call.call.cmd_id].append(call)
    for cmd_id, calls in cmdid2calls.items():
        for call in calls:
            for cb in pid2cb[call.pid]:
                instrtr2cmdid[cb.trace].append(cmd_id)
    log.debug(f"instrtr2cmdid: {instrtr2cmdid}")
    # the logic is that every command id will have a distinct trace
    # or at least there will be a majority of traces that have the exact same commandid
    nrids2data = defaultdict(list)
    for trace, ids in instrtr2cmdid.items():
        nrids2data[len(ids)].append(ids)
    cmdids = sorted(nrids2data)
    # assert len(cmdids) > 1, f"only one trace?? {cmdids}" # this isn't necessarily true, could be we did not enumerate enought command ids
    if len(cmdids) == 1:
        log.info(f"not enough command ids enumerated!")
        default_cmd_ids = []
    else:
        assert cmdids[-1] > cmdids[-2], f"multiple default traces?? {cmdids}"
        assert (
            len(nrids2data[cmdids[-1]]) == 1
        ), f"should only exist one default trace"
        default_cmd_ids = nrids2data[cmdids[-1]][0]
    # all other cmd ids are valid
    cmd_objs = []
    for cmd_id in cmdid2calls.keys():
        if cmd_id in default_cmd_ids:
            cmd_objs.append(Cmd(cmd_id, valid=False))
        else:
            cmd_objs.append(Cmd(cmd_id))
    return cmd_objs
