/*
Fuzzing script
*/

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

const cmnop = new CModule(`
    int nop(void* parcel, int pos) {
      return 0;
    }
    `);

function nop_AParcel_setDataPosition(){
    var processes = Process.enumerateModules();
    // _ZNK7android14IPCThreadState13getCallingPidEv
    for(let i = 0; i < processes.length; i++){
        //console.log(processes[i].name);
        if(!(processes[i].name === "libbinder_ndk.so")){
            continue;
        }
        console.log("hooking?", processes[i].name);
        let AParcel_setDataPosition = processes[i].findExportByName("AParcel_setDataPosition");
        if(AParcel_setDataPosition !== null){
            console.log("nopping out setDataPosition...");
            Interceptor.replace(AParcel_setDataPosition, cmnop.nop);
        } 
    }
}

nop_AParcel_setDataPosition();

const stalker_instrumentation = new CModule(`
    #include <gum/gumstalker.h>
    #include <stdint.h>
    #include <stdio.h>
    #include <string.h>
    #include <stdlib.h>

    typedef void (*logfunc)(int prio, const char *tag,  const char *fmt, ...);
    typedef struct Range {
        uint64_t start;
        uint64_t end;
        struct Range* next;
    } Range;

    extern void* (*malloc)(int size);
    extern uint8_t* frida_map;
    extern int frida_map_size; 
    extern logfunc log;
    extern Range* head;
    extern int do_log;

    static void libfuzzer_add_edge (GumCpuContext * cpu_context, gpointer user_data);

    /*
    * Setup API
    */

    void set_frida_map(uint8_t* instrumentation_map, int map_size){
        log(4, "fuzzer", "setting frida instrumentaiton map: 0x%lx, %d", instrumentation_map, map_size);
        frida_map = instrumentation_map;
        frida_map_size = map_size;
    }

    void enable_log() {
        do_log = 1;
    }

    void disable_log() {
        do_log = 0;
    }

    void print_status(){
        log(4, "fuzzer", "hi");
        log(4, "fuzzer", "frida_map: 0x%lx, frida_map_size: 0x%lx, head: 0x%lx, do_log: %d", frida_map, frida_map_size, head, do_log);
    }

    /*
    * Initialize code ranges to instrument
    * Check while fuzzing if range should be instrumented
    */
    
    int add_range(uint64_t start, uint64_t end) {
        Range* newRange = (Range*)malloc(sizeof(Range));
        newRange->start = start;
        newRange->end = end;
        newRange->next = NULL;
        // insert so that the items inserted first stay at the front of the list
        if(head == NULL){
            head = newRange;
        }
        else{
            Range* current = head;
            while(current->next != NULL){
                current = current->next;
            }
            current->next = newRange;
        }
        if(do_log && log){
            log(4, "fuzzer", "adding Range@%p(0x%lx,0x%lx)->next@%p", newRange, newRange->start, newRange->end, newRange->next);
        }
        return 0;
    }

    bool is_in_range(uintptr_t pc) {
        Range* current = head;
        while (current != NULL) {
            if(do_log && log){
                log(4, "fuzzer", "checking if pc:0x%lx is in range(0x%lx,0x%lx))", pc, current->start, current->end);
            }
            if (pc >= current->start && pc <= current->end) {
                if(do_log && log){
                    log(4, "fuzzer", "pc in range!");
                } 
                return true;
            }
            current = current->next;
        }
        if(do_log && log){
            log(4, "fuzzer", "pc not in range!");
        }
        return false;
    }

    uintptr_t get_offset(uintptr_t pc) {
        Range* current = head;
        while (current != NULL) {
            if(do_log && log){
                log(4, "fuzzer", "checking if pc:0x%lx is in range(0x%lx,0x%lx))", pc, current->start, current->end);
            }
            if (pc >= current->start && pc <= current->end) {
                if(do_log && log){
                    log(4, "fuzzer", "pc in range!");
                } 
                return pc - current->start;
            }
            current = current->next;
        }
        if(do_log && log){
            log(4, "fuzzer", "pc not in range! (SHOULD NOT HAPPEN!!)");
        }
        return 0; 
    }

    /*
    * Gum Stalker instrumentation, fired for each basic block instrumented
    */

    void transform (GumStalkerIterator * iterator, GumStalkerOutput * output, gpointer user_data) {
        cs_insn * insn;

        gum_stalker_iterator_next (iterator, &insn);

        if (is_in_range(insn->address)) {
            gum_stalker_iterator_put_callout (iterator, libfuzzer_add_edge, user_data, NULL);
        }
        
        gum_stalker_iterator_keep (iterator);

        while (gum_stalker_iterator_next (iterator, &insn)) {
            gum_stalker_iterator_keep (iterator);
        }
    }

    static void libfuzzer_add_edge (GumCpuContext * cpu_context, gpointer user_data) {
        guint64 cur_loc = cpu_context->${pc};
        guint64 rel_off = (guint64)get_offset((uintptr_t)cur_loc);
        uint8_t * libfuzzer_cov = frida_map;
        libfuzzer_cov[rel_off % frida_map_size]++;
        if(do_log && log){
            log(4, "fuzzer", "libfuzzer_add_edge PC: 0x%lx, 0x%lx, %d", cur_loc, cur_loc % frida_map_size, libfuzzer_cov[cur_loc % frida_map_size]);
        }
    }
`, {"malloc": malloc_native_storage, "log": logcat_native_storage, "frida_map": frida_map_native_storage, 'frida_map_size': frida_map_size_storage, 'do_log': do_log_native_storage, 'head': range_head_native_storage});

var set_frida_map = new NativeFunction(stalker_instrumentation.set_frida_map, 'void', ['pointer', 'uint']);
var add_instr_range = new NativeFunction(stalker_instrumentation.add_range, 'int', ['pointer', 'pointer']);
var native_print_status = new NativeFunction(stalker_instrumentation.print_status, 'void', []);
var enable_log = new NativeFunction(stalker_instrumentation.enable_log, 'void', []);
var disable_log = new NativeFunction(stalker_instrumentation.disable_log, 'void', []);


msync_Func = get_msync();
if(msync_Func === null){
    console.log("[!!] failed to find msync...");
    while(1){}
}
native_print_status();
console.log("[*] finished setup");

send(JSON.stringify({"type": "setup_done"}));

// from the python3 hook, set the necessary information
rpc.exports = {
    addrange(bin, start, end) {
        console.log("[*] setting instrumentation range", bin, start.toString(16), end.toString(16));
        add_instr_range(new NativePointer(start), new NativePointer(end));
        console.log("[*] done instrumenting");
    },
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
        // add onTransact module to range to instrument
        console.log("[*] adding range: ", ptr(onTransact_module.base), ptr(onTransact_module.base).add(onTransact_module.size));
        add_instr_range(ptr(onTransact_module.base), ptr(onTransact_module.base).add(onTransact_module.size));
        console.log("[*] done adding log"); 
    },
    setupshm(shm_path, shm_size){
        console.log("[*] setting shmpath, size", shm_path, shm_size);
        const shm_addr = _open_shm(shm_path, shm_size); 
        console.log("shm addr: ", shm_addr);
        if(shm_addr.toInt32() == -1){
            console.log("failed to shmat :(");
        } else {
            afl_area_ptr = shm_addr;
            console.log("[*] afl_area_ptr: " + ptr(afl_area_ptr));
            set_frida_map(ptr(afl_area_ptr), shm_size);
            console.log("[*] setup frida instrumentation map");
            //for testing: afl_area_ptr.writeUtf8String("AAAAAAAAAAAAAAasdf");
        }
    },
    filterpids(pid) {
        console.log("[*] setting up frida hook to filter by pid");
        do_pid_filter = true;
        fuzzer_pid = pid;
        //start_pid_filter(pid);
    },
    instrument() {
        console.log("[*] setting up instrumentation, hooking onTransact");
        native_print_status(); 
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

function get_msync(){
    const msync_addr = Module.findExportByName("libc.so", "msync");
    return new NativeFunction(msync_addr, 'int', ['pointer', 'int', 'int'])
}

function find_logcat(){
    logcat_print = Module.findExportByName(null, "__android_log_print");  
    logcat = new NativeFunction(logcat_print, 'int', ['int', 'pointer', 'pointer']);
    logcat_native_storage = Memory.alloc(0x8);
    logcat_native_storage.writePointer(logcat_print);
    console.log("[*] logcat addr: ", logcat_print);
}

// open shared memory
function _open_shm(shmem_path, shmem_size){
    const open_addr = Module.findExportByName("libc.so", "open");
    const open = new NativeFunction(open_addr, 'int', ['pointer', 'int', 'int']);
    const path_mem = Memory.allocUtf8String(shmem_path);
    const fd = open(path_mem, 0x2, 0x180);
    console.log("fd: ", fd);
    const mmap_addr = Module.findExportByName("libc.so", "mmap");
    const mmap = new NativeFunction(mmap_addr, 'pointer', ['pointer', 'int', 'int', 'int', 'int', 'int']); 
    const shmem_addr = mmap(ptr(0), shmem_size, 0x3, 0x1, fd, 0x0);
    console.log("shmem_addr: ", shmem_addr);
    afl_area_size = shmem_size;
    return shmem_addr;
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
    if(afl_area_ptr === null){
        console.log("AFL area ptr is 0!!!");
        return;
    }
    if(afl_area_size === null){
        console.log("AFL area size is 0!!!");
        return;
    }
    if(getCallingPid_Func === null){
        console.log("getCalllingPid_Func is null!!!");
        return;
    }

    const stalker_event_config = {
        call: false,
        ret: false,
        exec: false,
        block: false,
        compile: true, 
    };

    //TODO: add more fine-grained exclusions
    
    // Allocate a user_data struct to hold various information required in
        // our stalker callout:
        // 
        // struct _user_data {
        //   uint8_t *afl_area_ptr;
        //   uint64_t base;
        //   uintptr_t module_start;
        //   uintptr_t module_end;
        //   void (*log)(long); 
        //   uintptr_t do_log; 
        // };
        //
    

    const _user_data = Memory.alloc(0x100);
    _user_data.writePointer(afl_area_ptr);
    _user_data.add(8).writePointer(ptr(onTransact_module.base));
    _user_data.add(16).writePointer(ptr(onTransact_module.base));
    _user_data.add(24).writePointer(ptr(onTransact_module.base).add(onTransact_module.size))
    _user_data.add(32).writePointer(logcat_print);
    _user_data.add(40).writePointer(ptr(1)); // set to 0 to disable log printing
    user_data = _user_data;

    
    Interceptor.attach(onTransact, {
        onEnter(args) {
            do_logcat("start onTransact hook");
            if(do_pid_filter){
                let calling_pid = getCallingPid_Func();
                if(calling_pid != fuzzer_pid){
                    do_logcat("dropping request from: ", calling_pid);
                }
                else {
                    Stalker.follow({
                        events: stalker_event_config,
                        transform: stalker_instrumentation.transform,
                        data: ptr(_user_data),
                    });
                }
            } else {
                Stalker.follow({
                    events: stalker_event_config,
                    transform: stalker_instrumentation.transform,
                    data: ptr(_user_data),
                });
            }
        },
        onLeave(result){
            Stalker.unfollow();
            Stalker.flush();
            if (gc_counter > 300) {
                do_logcat("garbage colleciton");
                Stalker.garbageCollect();
                gc_counter = 0;
            }
            gc_counter++;
            //TODO: ensure that file changes are flushed to disk
            msync_Func(afl_area_ptr, afl_area_size, 4);
            do_logcat("done tracing");
        }
    });
}



