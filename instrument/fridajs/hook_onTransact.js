/*
 * Binder hooking script
 */

// from the python3 hook, set the necessary information
rpc.exports = {
    ping() {
        console.log("[*] pong!");
    }
  };

/* ======================================================================================================================== *
 * getCallingPid                                                                                                            *                                                                                                               *
 * ======================================================================================================================== */

function getCallingPid(proc_path){
    var processes = Process.enumerateModules();
    // _ZNK7android14IPCThreadState13getCallingPidEv
    for(let i = 0; i < processes.length; i++){
        if(processes[i].path === proc_path){
            var getIPCThreadStateSelf = processes[i].findExportByName("_ZN7android14IPCThreadState4selfEv");
            var getCallingPid = processes[i].findExportByName("_ZNK7android14IPCThreadState13getCallingPidEv");
            if(getCallingPid !== null && getIPCThreadStateSelf !== null){
                console.log("[*] found android::IPCThreadState::getCallingPid at: " + getCallingPid + " in process: " + processes[i].name);
                console.log("[*] found android::IPCThreadState::self at: " + getIPCThreadStateSelf + " in process: " + processes[i].name);
                var getIPCThreadStateSelf_Func = new NativeFunction(getIPCThreadStateSelf, 'pointer', []);
                var getCallingPid_Func = new NativeFunction(getCallingPid, 'int', ['pointer']);
                var ipcthreadstate = getIPCThreadStateSelf_Func();
                console.log("[**] callingpid_all self(): " + ipcthreadstate);
                var pid = getCallingPid_Func(ipcthreadstate);
                console.log("[**] callingpid_all pid(): " + pid);
                return pid;
            }
        }
    }
    return null; 
}    

/* ======================================================================================================================== *
 * BBinder::transact hook                                                                                                 *                                                                                                               *
 * ======================================================================================================================== */

function find_BBinder_transact(){
    var processes = Process.enumerateModules();
    var mm = new ModuleMap();
    // _ZNK7android14IPCThreadState13getCallingPidEv
    var out =  {};
    for(let i = 0; i < processes.length; i++){
        var BBinder_transact = processes[i].findExportByName("_ZN7android7BBinder8transactEjRKNS_6ParcelEPS1_j");
        if(BBinder_transact !== null){
            console.log("[*] BBinder::ontransact address: ", BBinder_transact);
            let module_path = mm.find(BBinder_transact).path;
            if(module_path !== null){
                out[module_path] = BBinder_transact;
                console.log("[*] module relevant: ", mm.find(BBinder_transact).path);
            }
        }
    }
    console.log("[*] find ontransact: ", JSON.stringify(out));
    return out;    
}

function hook_BBinder_transact(){
    var BBinder_transacts = find_BBinder_transact();
    if(Object.keys(BBinder_transacts).length == 0){
        console.log("[-] Failed to find _ZN7android7BBinder8transactEjRKNS_6ParcelEPS1_j... :(");
        return null;
    }
    for(var binary in BBinder_transacts){
        var BBinder_transact = BBinder_transacts[binary];
        Interceptor.attach(BBinder_transact, {
            onEnter(args) {
                console.log("BBinder onTransact hook! @", binary, BBinder_transact);
                var calling_pid = getCallingPid(binary);
                console.log("pids: ", calling_pid, curr_pid);
                if(calling_pid === curr_pid){
                    console.log("[*] handling weird getcurrentPid");
                    for(var bin_temp in BBinder_transacts){
                        console.log("???", bin_temp);
                        calling_pid = getCallingPid(bin_temp);
                        console.log("[*] checking ", bin_temp, calling_pid);
                        if(calling_pid != curr_pid){
                            var binary_getpid = bin_temp;
                            break;
                        }
                    }
                } else {
                    var binary_getpid = binary; 
                }
                var this_arg = args[0];
                console.log('this arg: ', this_arg);
                var this_vtable = this_arg.readPointer();
                console.log('this vtable: ', this_vtable);
                var onTransact_addr = (this_vtable.add(0x80)).readPointer();
                var getInterfaceDescriptor_addr = (this_vtable.add(0x8)).readPointer();
                console.log('getInterfaceDescriptor: ', getInterfaceDescriptor_addr);
                var getInterfaceDescriptor = new NativeFunction(getInterfaceDescriptor_addr, 'pointer', ['pointer']);
                var interface_name_obj = getInterfaceDescriptor(this_arg);
                var interface_name_s16 = interface_name_obj.readPointer();
                var interface_name = interface_name_s16.readUtf16String();
                console.log('interface name return value: ', interface_name); 
                console.log('onTransact addr: ', onTransact_addr);
                var moduleMap = new ModuleMap();
                var moduleName = moduleMap.getName(onTransact_addr);
                console.log('onTransact module addr: ', moduleName);
                // handle libbinder_ndk
                if(moduleName === "libbinder_ndk.so"){
                    console.log("handling libbinder_ndk.so");
                    var new_this = this_arg.sub(0x38);
                    var ndk_AiBinder_Class = (new_this.add(0x8)).readPointer();
                    // fucked, check if writeHeader field is present
                    var writeHeader_maybe = ndk_AiBinder_Class.readInt();
                    if(writeHeader_maybe == 0 || writeHeader_maybe == 1){
                        // writeHeader field is present (otherise this is a functionpointer)
                        onTransact_addr = (ndk_AiBinder_Class.add(0x18)).readPointer();
                    } else {
                        onTransact_addr = (ndk_AiBinder_Class.add(0x10)).readPointer();
                    }
                    console.log('onTransact addr: ', onTransact_addr);
                }
                console.log('[!] ===========BBinder::transact===========');
                console.log("[!] calling PID: " + calling_pid);
                console.log('[!] ===================================');
                let msg = {"type": "BBinder_transact_hook", "onTransact_addr": onTransact_addr.toString(), "InterfaceDescriptor": interface_name, "onTransact_module_type": moduleName, 
                    "binder_func": "android::BBinder::transact", "backtrace": Thread.backtrace(this.context, Backtracer.FUZZY).map(DebugSymbol.fromAddress).join(","), "calling_pid": calling_pid,
                    "BBinder_path": binary_getpid}
                send(JSON.stringify(msg));
            }
        });
    }
}


/* ======================================================================================================================== *
 * main                                                                                                                     *                                                                                                               *
 * ======================================================================================================================== */

console.log("[*] hooked!");
var curr_pid = Process.id;
// hook BBinder
hook_BBinder_transact();

console.log("[*] finished setup");
send(JSON.stringify({"type": "setup_done"}))
