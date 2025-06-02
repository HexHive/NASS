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

function get_getCallingPid(){
    var processes = Process.enumerateModules();
    // _ZNK7android14IPCThreadState13getCallingPidEv
    for(let i = 0; i < processes.length; i++){
        if(processes[i].path === "/system/lib64/libbinder.so"){
            var getIPCThreadStateSelf = processes[i].findExportByName("_ZN7android14IPCThreadState4selfEv");
            var getCallingPid = processes[i].findExportByName("_ZNK7android14IPCThreadState13getCallingPidEv");
            if(getCallingPid !== null && getIPCThreadStateSelf !== null){
                console.log("[*] found android::IPCThreadState::getCallingPid at: " + getCallingPid + " in process: " + processes[i].name);
                console.log("[*] found android::IPCThreadState::self at: " + getIPCThreadStateSelf + " in process: " + processes[i].name);
                var getIPCThreadStateSelf_Func = new NativeFunction(getIPCThreadStateSelf, 'pointer', []);
                var getCallingPid_Func = new NativeFunction(getCallingPid, 'int', ['pointer']); 
                var callingpid_all = function() {
                    var ipcthreadstate = getIPCThreadStateSelf_Func();
                    console.log("[**] callingpid_all self(): " + ipcthreadstate);
                    var pid = getCallingPid_Func(ipcthreadstate);
                    console.log("[**] callingpid_all pid(): " + pid);
                    return pid;
                };
                return callingpid_all;    
        }
        break;
        }
    }
    return null;
}

/* ======================================================================================================================== *
 * BBinder::transact hook                                                                                                 *                                                                                                               *
 * ======================================================================================================================== */

function find_BBinder_transact(){
    var processes = Process.enumerateModules();
    // _ZNK7android14IPCThreadState13getCallingPidEv
    for(let i = 0; i < processes.length; i++){
        if(processes[i].path === "/system/lib64/libbinder.so"){
            return processes[i].base.add(0x48dc0);
            var BBinder_transact = processes[i].findSymbolByName("_ZN7android14IPCThreadState14executeCommandEi");
            console.log("???")
            if(BBinder_transact !== null){
                console.log("thread execute: ", BBinder_transact);
                return BBinder_transact.add(0x380); //TODO update this for new devices
            } else {
                console.log("unable to find _ZN7android14IPCThreadState14executeCommandEi...");
            }
        }
    }
    return null;    
}

function hook_BBinder_transact(){
    var BBinder_transact = find_BBinder_transact();
    if(BBinder_transact === null){
        console.log("[-] Failed to find _ZN7android7BBinder8transactEjRKNS_6ParcelEPS1_j... :(");
        return null;
    }
    console.log("[!] bbinder transact hook: ", BBinder_transact);
    Interceptor.attach(BBinder_transact, {
        onEnter(args) {
            console.log("BBinder onTransact hook!");
            var calling_pid = getCallingPid_Func();
            //console.log("x8: ", this.context.x8);
            var this_arg = this.context.x23;
            console.log('this arg: ', this_arg);
            var this_vtable = this_arg.readPointer(); //TODO: change this to reading x8
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
            let msg = {"type": "BBinder_transact_hook", "onTransact_addr": onTransact_addr.toString(), "InterfaceDescriptor": interface_name, "onTransact_module_type": moduleName, "binder_func": "android::BBinder::transact", 
                        BBinder_path: "/system/lib64/libbinder.so", "backtrace": Thread.backtrace(this.context, Backtracer.FUZZY).map(DebugSymbol.fromAddress).join(","), "calling_pid": calling_pid}
            send(JSON.stringify(msg));
        }
    });
}

/* ======================================================================================================================== *
 * main                                                                                                                     *                                                                                                               *
 * ======================================================================================================================== */

console.log("[*] hooked!");
var getCallingPid_Func = get_getCallingPid();
if(getCallingPid_Func === null){
    console.log("[!!] failed to find getCallingPid...");
    while(1){
    }
}

// hook BBinder
hook_BBinder_transact();

console.log("[*] finished setup");
send(JSON.stringify({"type": "setup_done"}))
