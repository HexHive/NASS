/*
 * Binder hooking script
 */

var binder_funcs_hook = [];
var binder_func_names = [];
var onTransact = null;
var onTransact_module = null;
var onTransact_bin = null;
var BBinder_path = null;
var getCallingPid_Func = null;
var call_counter = 0;

const cmnop = new CModule(`
    int nop(void* parcel, int pos) {
      return 0;
    }
    `);

function find_AParcel_setDataPosition(){
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
            return AParcel_setDataPosition;
        } 
    }
    return null;
}

function get_AIBinder_getUserData(){
    var processes = Process.enumerateModules();
    for(let i = 0; i < processes.length; i++){
        var AIBinder_getUserData = processes[i].findExportByName("AIBinder_getUserData");
        if(AIBinder_getUserData !== null){
            console.log("[*] found AIBinder_getUserData at: " + AIBinder_getUserData + " in process: " + processes[i].name);
            return new NativeFunction(AIBinder_getUserData, 'pointer', ['pointer']);
            break;
        }
    }
    return null;
}
var binder_module = null;

// from the python3 hook, set the necessary information
rpc.exports = {
    ping() {
        console.log("[*] pong!");
    },
    setonstransact(onTransact_addr, onTransact_binary, BBinder_path_arg, onT_binder_module){
        // get getpidpath
        BBinder_path = BBinder_path_arg;
        // get onTransact 
        onTransact_bin = onTransact_binary;
        console.log("onTransact bin:", onTransact_bin);
        onTransact_module = Process.getModuleByName(onTransact_bin);
        onTransact = onTransact_module.base.add(onTransact_addr);
        binder_module = onT_binder_module;
        console.log("[*] setting onTransact: ", onTransact);
    },
    instrument() {
        console.log("[*] setting up instrumentation, hooking onTransact");
        start_hook();
    }
};


function start_hook(){
    if(onTransact === null || onTransact_bin === null){
        console.log("[-] ERROR onTransact is null!");
        return;
    }
    Interceptor.attach(onTransact, {
        onEnter(args) {
            let b = args[0];
            if(binder_module == "libbinder_ndk.so"){
                let userdata = AIBinder_getUserData(b);
                let something = userdata.readPointer();
                console.log("something: ", something);
                var vtable = something.readPointer();
                console.log("vtable: ", vtable);
                
            } else {
                var vtable = b.add(-0x8).readPointer();
                console.log("vtable: ", vtable); 
                console.log("TODO...");
            }
            let data = {};
            let off = 0x0;
            while(1){
                let fptr = vtable.add(off).readPointer();
                if(fptr.isNull()){
                    break;
                }
                let mod = Process.findModuleByAddress(fptr);
                if(mod !== null){
                    data[off.toString(16)] = {
                        "module": mod.path,
                        "offset": fptr - mod.base
                    }
                }
                console.log(fptr);
                off += 0x8;
            }
            send(JSON.stringify(data))
        },
        onLeave(result){
        }
    });
}


/* ======================================================================================================================== *
 * main                                                                                                                     *                                                                                                               *
 * ======================================================================================================================== */

console.log("[*] hooked!");
var curr_pid = Process.id;

var AIBinder_getUserData = get_AIBinder_getUserData();
console.log("AIBinder getUserData: ", AIBinder_getUserData);

console.log("[*] finished setup");
send(JSON.stringify({"type": "setup_done"}))
