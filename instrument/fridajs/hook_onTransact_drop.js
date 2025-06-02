/*
 * Binder hooking script, test what happens to the phone if we start dropping binder requests
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
        var BBinder_transact = processes[i].findExportByName("_ZN7android7BBinder8transactEjRKNS_6ParcelEPS1_j");
        if(BBinder_transact !== null){
            return BBinder_transact;
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
    Interceptor.attach(BBinder_transact, {
        onEnter(args) {
            var calling_pid = getCallingPid_Func();
            var this_arg = args[0];
            console.log('this arg: ', this_arg);
            var cmd_id = args[1];
            console.log('cmd_id: ', cmd_id);
            args[1] = new NativePointer(0x5f504944);
            console.log('[!] ===========BBinder::transact===========');
            console.log("[!] calling PID: " + calling_pid);
            console.log('[!] ===================================');
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