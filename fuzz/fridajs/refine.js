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

function find_unsafeTypedArray(){
    var processes = Process.enumerateModules();
    let out = [];
    for(let i = 0; i < processes.length; i++){
        var exp = processes[i].enumerateExports();
        if(exp == null){
            continue;
        }
        for(let i = 0; i < exp.length; i++){
            if(exp[i].name.includes("7android6Parcel21unsafeReadTypedVector")){
                console.log("[*] found unsafeReadTypedVector...");
                out.push(exp[i].address);
            }
        }
    }
    return out;
}

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

function hook_setDataPosition(parcel, offset){
    console.log("hook setDataPosition called...");
    call_counter += 1;
    let calling_pid = getCallingPid_Func();
    let msg = {
        "type": "AParcel_setDataPosition", "pid": calling_pid, 
        "call_counter": call_counter, 
        "name": "AParcel_setDataPosition" 
    } 
    console.log("[*] sending: ", JSON.stringify(msg));
    send(JSON.stringify(msg));
    return 0;
}

var _hook_setDataPosition = new NativeCallback(hook_setDataPosition, 'int', ['pointer', 'int']);

// from the python3 hook, set the necessary information
rpc.exports = {
    ping() {
        console.log("[*] pong!");
    },
    setonstransact(onTransact_addr, onTransact_binary, BBinder_path_arg){
        // get getpidpath
        BBinder_path = BBinder_path_arg;
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
    addtohook(func_name) {
	console.log("[*] addtohook, ", func_name);
        if(BBinder_path === null){
            console.log("[-] BBinder_path is none");
        }
        console.log("[*] adding binder func to hook: ", func_name);
        let processes = Process.enumerateModules();
        for(let i = 0; i < processes.length; i++){
            if(processes[i].path === BBinder_path){
                let func_hook = processes[i].findExportByName(func_name) ;
                if(func_hook !== null){
                    binder_funcs_hook.push(func_hook);
                    binder_func_names.push(func_name);
                } else {
                    let func_hook = Module.findExportByName(null, func_name);
                    if(func_hook !== null){
                        binder_funcs_hook.push(func_hook);
                        binder_func_names.push(func_name); 
                    } else {
                        console.log("[-] unable to find func", func_name, processes[i].path);
                    }
                }
            };
        };
    },
    instrument() {
        console.log("[*] setting up instrumentation, hooking onTransact");
        start_hook();
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

function start_hook(){
    if(onTransact === null || onTransact_bin === null){
        console.log("[-] ERROR onTransact is null!");
        return;
    }
    if(getCallingPid_Func === null){
        console.log("getCalllingPid_Func is null!!!");
        return;
    }
    Interceptor.attach(onTransact, {
        onEnter(args) {
            console.log("[*] start onTransact hook");
            console.log("[*] args: ", args[0], args[1], args[2], args[3]);
            this.calling_pid = getCallingPid_Func();
            this.parcel = args[2];
            call_counter = 0;

            this.binder_hooks = [];
            this.assocClass_hook = null;
            this.AParcel_readParcelableArray_hook = null;
            this.AParcel_setDataPosition_replaced = false;
            this.readunsafeTypedArray_hooks = [];

            for (let i = 0; i < binder_funcs_hook.length; i++) {
                console.log("[*] hooking, ", binder_funcs_hook[i], binder_func_names[i]);
                try{
                    let int = hook_binder_func(i, this.calling_pid, this.parcel.toString(), binder_funcs_hook[i]);
                    this.binder_hooks.push(int);
                } catch (error) {
                    console.log(error);
                }
            }
            if(AiBinder_associateClass !== null){
                console.log("[*] hooking associateClass");
                let int = hook_associateClass(AiBinder_associateClass);
                this.assocClass_hook = int;
            }
            if(AParcel_readParcelableArray !== null){
                console.log("[*] hooking readParcelableArray");
                let int = hook_readParcelableArray(AParcel_readParcelableArray, this.calling_pid);
                this.AParcel_readParcelableArray_hook = int;
            }
            if(AParcel_setDataPosition !== null){
                console.log("[*] replacing setDataPosition");
                Interceptor.replace(AParcel_setDataPosition, _hook_setDataPosition);
                this.AParcel_setDataPosition_replaced = true;
            }
            for( let i = 0; i < readUnsafeTypedArrays.length; i++){
                let int = hook_unsafeTypedArray(i, this.calling_pid, this.parcel.toString(), readUnsafeTypedArrays[i]);
                this.readunsafeTypedArray_hooks.push(int);
            }
        },
        onLeave(result){
            console.log("[*] finish onTransact hook");
            for (let i = 0; i < this.binder_hooks.length; i++) {
                let intc = this.binder_hooks[i];
                intc.detach();
            }
            if(AiBinder_associateClass !== null){
                this.assocClass_hook.detach();
                this.assocClass_hook = null;
            }
            if(this.AParcel_setDataPosition_replaced){
                Interceptor.revert(AParcel_setDataPosition);
                this.AParcel_setDataPosition_replaced = false;
            }
            for(let i=0; i<this.readunsafeTypedArray_hooks.length; i++){
                let intc = this.readunsafeTypedArray_hooks[i];
                intc.detach();
            }
            let msg = {"type": "onTransact_end", "pid": this.calling_pid, "call_counter": call_counter+1};
            send(JSON.stringify(msg));
        }
    });
}

function hook_binder_func(idx, calling_pid, parcel_arg, binder_func_to_hook){
    let intc = Interceptor.attach(binder_func_to_hook, {
        onEnter(args) {
            console.log("[*] hooked: ", binder_func_names[idx]);
            console.log("[*] args: ", args[0], args[1], args[2], args[3]);
            console.log("[*] original parcel ", parcel_arg);
            this.relevant = false;
            this.pid = -1;
            if(args[0].toString() !== parcel_arg){
                console.log("[!] not the same parcel data.");
                return;
            }
            let calling_pid_2 = getCallingPid_Func();
            if(calling_pid_2 === calling_pid){
                call_counter += 1;
                this.relevant = true;
                this.pid = calling_pid;
                console.log("[*] matching callingpid");
                let msg = {"type": "Binderfunc", "pid": calling_pid_2, "call_counter": call_counter, 
                    "name": binder_func_names[idx]
                }        
                console.log("[*] sending: ", JSON.stringify(msg));
                send(JSON.stringify(msg));
            } 
        },
        onLeave(result){
            if(this.relevant){
                call_counter += 1;
		console.log("result: " + result);
                console.log("exiting relevant binder function!");
                let msg = {"type": "Binderfunc_exit", "pid": this.pid, "call_counter": call_counter, 
                    "name": binder_func_names[idx]
                }   
                console.log("[*] sending: ", JSON.stringify(msg));
                send(JSON.stringify(msg));
            }
        }
    });
    return intc;
}

function hook_associateClass(assocClass_hook){
    let int = Interceptor.attach(assocClass_hook, {
        onEnter(args) {
            console.log("[*] hooked: AIBinder_associateClass");
            console.log("[*] args: ", args[0], args[1]);
            console.log("[*] matching callingpid");
            let interface_name_ptr_ptr = args[1].add(0x48);
            console.log("[*] interface name ptr**: ", interface_name_ptr_ptr);
            let interface_name_ptr = interface_name_ptr_ptr.readPointer();
            console.log("[*] interface name ptr: ", interface_name_ptr);
            let interface_name = interface_name_ptr.readUtf16String(); 
            console.log("[*] interface name: ", interface_name);
            let msg = {"type": "assocClass", 
                "name": interface_name
            }        
            console.log("[*] sending: ", JSON.stringify(msg));
            send(JSON.stringify(msg));
        },
        onLeave(result){
        }
    });
    return int;
}

function hook_readParcelableArray(readPA, calling_pid){
    let int = Interceptor.attach(readPA, {
        onEnter(args) {
            console.log("[*] hooked: readParcelableArray");
            console.log("[*] matching callingpid");
            let calling_pid_2 = getCallingPid_Func();
            if(calling_pid_2 === calling_pid){
                call_counter += 1;
                this.relevant = true;
                this.pid = calling_pid;
                console.log("[*] matching callingpid");
                let msg = {
                    "type": "readParcelableArray", "pid": calling_pid_2, 
                    "call_counter": call_counter, 
                    "name": "AParcel_readParcelableArray" 
                }        
                console.log("[*] sending: ", JSON.stringify(msg));
                send(JSON.stringify(msg));
            }  
        },
        onLeave(result){
            if(this.relevant){
                call_counter += 1;
		        console.log("result: " + result);
                console.log("exiting relevant binder function!");
                let msg = {"type": "readParcelableArray_exit", "pid": this.pid, "call_counter": call_counter, 
                    "name": "AParcel_readParcelableArray"
                }   
                console.log("[*] sending: ", JSON.stringify(msg));
                send(JSON.stringify(msg));
            }
        }
    });
    return int;
}

function hook_unsafeTypedArray(idx, calling_pid, parcel_arg, readUnsafeTP){
    let intc = Interceptor.attach(readUnsafeTP, {
        onEnter(args) {
            console.log("[*] hooked: unsafeReadTypedVector", readUnsafeTP);
            console.log("[*] args: ", args[0], args[1], args[2], args[3]);
            console.log("[*] original parcel ", parcel_arg);
            this.relevant = false;
            this.pid = -1;
            if(args[0].toString() !== parcel_arg){
                console.log("[!] not the same parcel data.");
                return;
            }
            let calling_pid_2 = getCallingPid_Func();
            if(calling_pid_2 === calling_pid){
                call_counter += 1;
                this.relevant = true;
                this.pid = calling_pid;
                console.log("[*] matching callingpid");
                let msg = {"type": "Binderfunc", "pid": calling_pid_2, "call_counter": call_counter, 
                    "name": "unsafeReadTypedVector" 
                }        
                console.log("[*] sending: ", JSON.stringify(msg));
                send(JSON.stringify(msg));
            } 
        },
        onLeave(result){
            if(this.relevant){
                call_counter += 1;
		console.log("result: " + result);
                console.log("exiting relevant binder function!");
                let msg = {"type": "Binderfunc_exit", "pid": this.pid, "call_counter": call_counter, 
                    "name": "unsafeReadTypedVector" 
                }   
                console.log("[*] sending: ", JSON.stringify(msg));
                send(JSON.stringify(msg));
            }
        }
    });
    return intc;
}

function find_associateClass(){
    var processes = Process.enumerateModules();
    // _ZNK7android14IPCThreadState13getCallingPidEv
    for(let i = 0; i < processes.length; i++){
        var AiBinder_associateClass = processes[i].findExportByName("AIBinder_associateClass");
        if(AiBinder_associateClass !== null){
            return AiBinder_associateClass;
        } 
    }
    return null;
}

function find_AParcel_readParcelableArray(){
    var processes = Process.enumerateModules();
    // _ZNK7android14IPCThreadState13getCallingPidEv
    for(let i = 0; i < processes.length; i++){
        var AParcel_readParcelableArray = processes[i].findExportByName("AParcel_readParcelableArray");
        if(AParcel_readParcelableArray !== null){
            return AParcel_readParcelableArray;
        } 
    }
    return null;
}



/* ======================================================================================================================== *
 * main                                                                                                                     *                                                                                                               *
 * ======================================================================================================================== */

console.log("[*] hooked!");
var curr_pid = Process.id;

var AiBinder_associateClass = find_associateClass();
console.log("[*] AIBinder_associateClass: ", AiBinder_associateClass);

var AParcel_readParcelableArray = find_AParcel_readParcelableArray();
console.log("[*] AParcel_readParcelableArray: ", AParcel_readParcelableArray);

var readUnsafeTypedArrays = find_unsafeTypedArray();
console.log("[*] Unsafe Typed Arrays", readUnsafeTypedArrays);

var AParcel_setDataPosition = null;
var AParcel_setDataPosition = find_AParcel_setDataPosition();
console.log("[*] AParcel_setDataPosition: ", AParcel_setDataPosition);

console.log("[*] finished setup");
send(JSON.stringify({"type": "setup_done"}))
