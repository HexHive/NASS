/*
 Collect DrCov coverage
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
do_log_native_storage.writeInt(0x1); //TODO FIXME do this based on flag

const malloc_addr = Module.findExportByName("libc.so", "malloc");
var malloc_native_storage = Memory.alloc(0x10);
malloc_native_storage.writePointer(malloc_addr);
var malloc_func = new NativeFunction(malloc_addr, 'pointer', ['int']);
console.log("[*] malloc function pointer: ", malloc_func);

var whitelist = [];

find_logcat();
if(logcat === null || logcat_print === null){
    console.log("[!!] failed to find logcat...");
    while(1){}
}

function make_maps() {
    var maps = Process.enumerateModulesSync();
    var i = 0;
    // We need to add the module id
    maps.map(function(o) { o.id = i++; });
    // .. and the module end point
    maps.map(function(o) { o.end = o.base.add(o.size); });
    return maps;
}

var maps = make_maps()
send(JSON.stringify({"type": "maps", 'map': maps}));

var module_ids = {};

maps.map(function (e) {
    module_ids[e.path] = {id: e.id, start: e.base};
});

const cmnop = new CModule(`
    int nop(void* parcel, int pos) {
      return 0;
    }
    `);

function nop_AParcel_setDataPosition(){
    var processes = Process.enumerateModules();
    // _ZNK7android14IPCThreadState13getCallingPidEv
    for(let i = 0; i < processes.length; i++){
        console.log(processes[i].name);
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

console.log("[*] finished setup");
send(JSON.stringify({"type": "setup_done"}));

// from the python3 hook, set the necessary information
rpc.exports = {
    addrange(bin) {
        console.log("[*] setting whitelist range", bin);
        whitelist.push(bin)
    },
    setontransact(onTransact_addr, onTransact_binary, BBinder_path){
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
        console.log("[*] setting whitelist range", onTransact_module.path);
        whitelist.push(onTransact_module.path);
        console.log("[*] done adding log"); 
    },
    filterpids(pid) {
        console.log("[*] setting up frida hook to filter by pid");
        fuzzer_pid = pid;
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

// Get the module map


// We want to use frida's ModuleMap to create DRcov events, however frida's
//  Module object doesn't have the 'id' we added above. To get around this,
//  we'll create a mapping from path -> id, and have the ModuleMap look up the
//  path. While the ModuleMap does contain the base address, if we cache it
//  here, we can simply look up the path rather than the entire Module object.


function drcov_bbs(bbs, fmaps, path_ids) {
    // We're going to use send(..., data) so we need an array buffer to send
    //  our results back with. Let's go ahead and alloc the max possible
    //  reply size

    /*
        // Data structure for the coverage info itself
        typedef struct _bb_entry_t {
            uint   start;      // offset of bb start from the image base
            ushort size;
            ushort mod_id;
        } bb_entry_t;
    */

    var entry_sz = 8;

    var bb = new ArrayBuffer(entry_sz * bbs.length);

    var num_entries = 0;

    for (var i = 0; i < bbs.length; ++i) {
        var e = bbs[i];

        var start = e[0];
        var end   = e[1];

        var path = fmaps.findPath(start);

        if (path == null) { continue; }

        var mod_info = path_ids[path];

        var offset = start.sub(mod_info.start).toInt32();
        var size = end.sub(start).toInt32();
        var mod_id = mod_info.id;

        // We're going to create two memory views into the array we alloc'd at
        //  the start.

        // we want one u32 after all the other entries we've created
        var x =  new Uint32Array(bb, num_entries * entry_sz, 1);
        x[0] = offset;

        // we want two u16's offset after the 4 byte u32 above
        var y = new Uint16Array(bb, num_entries * entry_sz + 4, 2);
        y[0] = size;
        y[1] = mod_id;

        ++num_entries;
    }

    // We can save some space here, rather than sending the entire array back,
    //  we can create a new view into the already allocated memory, and just
    //  send back that linear chunk.
    return new Uint8Array(bb, 0, num_entries * entry_sz);
}

// setup hook that starts stalker when the 
function setup_instr(){
    if(onTransact === null || onTransact_bin === null){
        console.log("[-] ERROR onTransact is null!");
        return;
    }
    if(getCallingPid_Func === null){
        console.log("getCalllingPid_Func is null!!!");
        return;
    }

    var filtered_maps = new ModuleMap(function (m) {
        if (whitelist.indexOf('all') >= 0) { return true; }
        let out = whitelist.some(item => item.toLowerCase().includes(m.name.toLowerCase()));
        return out;
    });

    Stalker.trustThreshold = 0;    
    Interceptor.attach(onTransact, {
        onEnter(args) {
            do_logcat("start onTransact hook");
	    console.log("[*] onTransact hook");
            let calling_pid = getCallingPid_Func();
            /*if(calling_pid != fuzzer_pid){
                do_logcat("dropping request from: "+ calling_pid.toString());
            }
            else {*/
            Stalker.follow({
                events: {
                    compile: true
                },
                onReceive: function (event) {
                    var bb_events = Stalker.parse(event,
                        {stringify: false, annotate: false});
                    var bbs = drcov_bbs(bb_events, filtered_maps, module_ids);
    
                    // We're going to send a dummy message, the actual bb is in the
                    //  data field. We're sending a dict to keep it consistent with
                    //  the map. We're also creating the drcov event in javascript,
                    // so on the py recv side we can just blindly add it to a set.
                    send(JSON.stringify({type: 'bbs', bbs: 1, caller_pid: calling_pid}), bbs);
                }
            });
            //}
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
            do_logcat("done tracing");
        }
    });
}



