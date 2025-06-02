//Credit: https://github.com/ttdennis/fpicker/blob/main/harness/stalker-instrumentation.js

let pc = undefined;
if (Process.arch == "x64") {
  pc = "rip";
} else if (Process.arch.startsWith("arm")) {
  pc = "pc";
} else if (Process.arch.startsWith("ia32")) {
  pc = "eip";
} else {
  console.log("[!] Unknown architecture!", Process.arch);
}

var onTransact = null;
var onTransact_module = null;
var onTransact_bin = null;
var getCallingPid_Func = null;
var msync_Func = null;
var afl_area_ptr = null;
var afl_area_size = null;
var gc_counter = 0;
var user_data = null;
var shm_id = null;
var logcat_print = null;
var logcat = null;
var logcat_native_storage = null;
var do_pid_filter = false;
var fuzzer_pid = null;
var frida_map_native_storage = Memory.alloc(0x10);
frida_map_native_storage.writePointer(new NativePointer(0x0));
var frida_map_size_storage = Memory.alloc(0x10);
frida_map_size_storage.writePointer(new NativePointer(0x0));
var range_head_native_storage = Memory.alloc(0x10);
range_head_native_storage.writePointer(new NativePointer(0x0));
var do_log_native_storage = Memory.alloc(0x10);
do_log_native_storage.writeInt(0x0); //TODO FIXME do this based on flag

const malloc_addr = Module.findExportByName("libc.so", "malloc");
var malloc_native_storage = Memory.alloc(0x10);
malloc_native_storage.writePointer(malloc_addr);
var malloc_func = new NativeFunction(malloc_addr, 'pointer', ['int']);
console.log("[*] malloc function pointer: ", malloc_func);

find_logcat();
if(logcat === null || logcat_print === null){
    console.log("[!!] failed to find logcat...");
    while(1){}
}

console.log("[*] finished setup");

send(JSON.stringify({"type": "setup_done"}));

// from the python3 hook, set the necessary information
rpc.exports = {
    setonstransact(onTransact_addr, onTransact_binary, BBinder_path){
        // get getpidpath
        getCallingPid_Func = get_getCallingPid(BBinder_path);
        if(getCallingPid_Func === null){
            console.log("[-] failed to find getcallingpid...");
        }
        // get onTransact 
        onTransact_bin = onTransact_binary;
        console.log("onTransact bin:", onTransact_bin);
        onTransact_module = Process.getModuleByName(onTransact_bin);
        onTransact = onTransact_module.base.add(onTransact_addr);
        console.log("[*] setting onTransact: ", onTransact);
    },
    instrument() {
        console.log("[*] setting up instrumentation, hooking onTransact");
        setup_instr();
    },
    ping() {
        console.log("[*] pong!");
    }
};

/* ======================================================================================================================== *
 * getCallingPid                                                                                                            *                                                                                                               *
 * ======================================================================================================================== */

function get_getCallingPid(path){
    var processes = Process.enumerateModules();
    // _ZNK7android14IPCThreadState13getCallingPidEv
    for(let i = 0; i < processes.length; i++){
        if(processes[i].path === path){
            var getIPCThreadStateSelf = processes[i].findExportByName("_ZN7android14IPCThreadState4selfEv");
            var getCallingPid = processes[i].findExportByName("_ZNK7android14IPCThreadState13getCallingPidEv");
            if(getCallingPid !== null && getIPCThreadStateSelf !== null){
                console.log("[*] found android::IPCThreadState::getCallingPid at: " + getCallingPid + " in process: " + processes[i].name);
                console.log("[*] found android::IPCThreadState::self at: " + getIPCThreadStateSelf + " in process: " + processes[i].name);
                var getIPCThreadStateSelf_Func = new NativeFunction(getIPCThreadStateSelf, 'pointer', []);
                var getCallingPid_Func_int = new NativeFunction(getCallingPid, 'int', ['pointer']); 
                var callingpid_all = function() {
                    var ipcthreadstate = getIPCThreadStateSelf_Func();
                    //console.log("[**] callingpid_all self(): " + ipcthreadstate);
                    var pid = getCallingPid_Func_int(ipcthreadstate);
                    //console.log("[**] callingpid_all pid(): " + pid);
                    return pid;
                };
                return callingpid_all;
            }
        }
    }
    return null;
}


function find_logcat(){
    logcat_print = Module.findExportByName(null, "__android_log_print");  
    logcat = new NativeFunction(logcat_print, 'int', ['int', 'pointer', 'pointer']);
    logcat_native_storage = Memory.alloc(0x8);
    logcat_native_storage.writePointer(logcat_print);
    console.log("[*] logcat addr: ", logcat_print);
}

function do_logcat(msg){
    let msg_ptr = Memory.allocUtf8String(msg);
    let fuzz_string = Memory.allocUtf8String("fuzzer");
    logcat(4, fuzz_string, msg_ptr);
}

// setup hook that starts stalker when the 
function setup_instr(){
    if(onTransact === null || onTransact_bin === null){
        console.log("[-] ERROR onTransact is null!");
        return;
    }
    
    Interceptor.attach(onTransact, {
        onEnter(args) {
            do_logcat("[*]onTransact hook hit: " + args[1]);
            send(JSON.stringify({"type": "ipcCapture", "command_id": args[1]}));
        },
        onLeave(result){
        }
    });
}



