/*
 * Binder hooking script
 */

var CALL_CTR = 0;

// from the python3 hook, set the necessary information
rpc.exports = {
    ping() {
        console.log("[*] pong!");
    }
  };

/* ======================================================================================================================== *
 * libbinder.so hooking                                                                                                     *                                                                                                               *
 * ======================================================================================================================== */

function is_mangled_parcel(mangled_name) {
    // look for android::parcel functions and return the functionname
    console.log("[*] looking for android::parcel");
    var start = mangled_name.substring(0,2);
    //console.log("[*] start of function: ", start);
    if(start != "_Z"){
        return null;
    }
    var fname_start = 3;
    while(1){
        if(mangled_name.substring(fname_start,fname_start+1) == "N" || mangled_name.substring(fname_start,fname_start+1)== "K"){
            fname_start +=1;
        } else {
            break;
        }
    }
    var android_len = parseInt(mangled_name.substring(fname_start,fname_start+1));
    //console.log("[*] fname len start: " + android_len)
    if(android_len != 7){
        return null;
    }    
    var android = mangled_name.substring(fname_start+1,fname_start+1+android_len);
    //console.log("[*] android: " + android);
    if(android != "android"){
        return null;
    }
    var parcel_start = fname_start+1+android_len;
    var parcel_len = parseInt(mangled_name.substring(parcel_start,parcel_start+1));
    //console.log("[*] parcel len: " + parcel_len);
    if(parcel_len != 6){
        return null;
    }
    var parcel = mangled_name.substring(parcel_start+1,parcel_start+1+parcel_len);
    //console.log("[*] parcel: " + parcel);
    if(parcel != "Parcel"){
        return null;
    }
    var fname_len = "";
    var fname_len_start = parcel_start+1+parcel_len;
    var read;
    var idx = 0;
    while(1){
        read = parseInt(mangled_name.substring(fname_len_start+idx, fname_len_start+idx+1))
        //console.log("[*] lenght enum, read: " + read);
        if(Number.isNaN(read)){
            break;
            }
        idx += 1;
    }
    fname_len  = parseInt(mangled_name.substring(fname_len_start, fname_len_start+idx));
    //console.log("[*] function name length: " + fname_len);
    var fname = mangled_name.substring(fname_len_start+idx, fname_len_start+idx+fname_len);
    console.log("[*] function name: " + fname);
    return fname;
}

function get_parcel_extracting() {
    var parcel_extract_functions = [];
    console.log("[*] hooking android::parcel::read* functions...");
    var libbinder = Process.findModuleByName("libbinder.so");
    if(libbinder == null){
        console.log("[*] failed to find libbinder :(");
        return -1;
    } 
    var libbinder_exp = libbinder.enumerateExports();
    if(libbinder_exp == null){
        console.log("[*] failed to get libbinder exports");
        return -1;
    }
    for(let i = 0; i < libbinder_exp.length; i++){
        console.log(libbinder_exp[i].type, libbinder_exp[i].name);
        // some logic to find the read functions
        var fname = is_mangled_parcel(libbinder_exp[i].name);
        if(fname == null){
            continue;
        }
        console.log("[****] fname: " + fname);
        if(fname.substring(0,4) == "read"){
            parcel_extract_functions.push(libbinder_exp[i]);
        }
        if(fname.substring(0,5) == "check"){
            parcel_extract_functions.push(libbinder_exp[i]);
        }
    }
    return parcel_extract_functions;
}

function hook_parcel_extracting(funcs_to_hook) {
    for(let i = 1; i< funcs_to_hook.length; i++){
        console.log("[*] trying to hook: " + funcs_to_hook[i].name);
        try{
            Interceptor.attach(funcs_to_hook[i].address, {
            onEnter(args) {
                var calling_pid = getCallingPid_Func();
                console.log('[!] ===========libbinder==============');
                console.log("[!] just called: " + funcs_to_hook[i].name);
                console.log("[!] calling PID: " + calling_pid);
                console.log('backtrace :\n' +
                Thread.backtrace(this.context, Backtracer.FUZZY)
                .map(DebugSymbol.fromAddress).join('\n'));
                console.log('[!] call ctr: ' + CALL_CTR) + '\n';
                console.log('[!] ==================================');
                let msg = {"type": "binder_recv_hook", "binder_func": funcs_to_hook[i].name, "backtrace": Thread.backtrace(this.context, Backtracer.FUZZY).map(DebugSymbol.fromAddress).join(","), "ctr": CALL_CTR, "calling_pid": calling_pid}
                CALL_CTR = CALL_CTR + 1;
                send(JSON.stringify(msg));
            }
        })
        } catch {
            console.log("[*] failed to hook...")
        }
        console.log("[*] hooked: " + funcs_to_hook[i].name);
    }
}

/* ======================================================================================================================== *
 * libbinder_ndk.so hooking                                                                                                     *                                                                                                               *
 * ======================================================================================================================== */

function is_AParcel_read(fname){
    if(fname.substring(0,12) === "AParcel_read"){
        return fname;
    }
    return  null;
}

function get_parcel_extracting_ndk() {
    var parcel_extract_functions = [];
    console.log("[*] hooking AParcel_read* functions...");
    var libbinder = Process.findModuleByName("libbinder_ndk.so");
    if(libbinder == null){
        console.log("[*] failed to find libbinder_ndk :(");
        return -1;
    } 
    var libbinder_exp = libbinder.enumerateExports();
    if(libbinder_exp == null){
        console.log("[*] failed to get libbinder exports");
        return -1;
    }
    for(let i = 0; i < libbinder_exp.length; i++){
        console.log(libbinder_exp[i].type, libbinder_exp[i].name);
        var fname = is_AParcel_read(libbinder_exp[i].name);
        if(fname == null){
            continue;
        }
        console.log("*********FOUND******************");
        parcel_extract_functions.push(libbinder_exp[i])
    }
    return parcel_extract_functions;
}

function hook_parcel_extracting_ndk(funcs_to_hook) {
    for(let i = 1; i< funcs_to_hook.length; i++){
        console.log("[*] trying to hook: " + funcs_to_hook[i].name);
        try{
            Interceptor.attach(funcs_to_hook[i].address, {
            onEnter(args) {
                var calling_pid = getCallingPid_Func();
                console.log('[!] ===========libbinder_ndk===========');
                console.log("[!] just called: " + funcs_to_hook[i].name);
                console.log("[!] calling PID: " + calling_pid);
                console.log('backtrace :\n' +
                Thread.backtrace(this.context, Backtracer.FUZZY)
                .map(DebugSymbol.fromAddress).join('\n'));
                console.log('[!] call ctr: ' + CALL_CTR) + '\n';
                console.log('[!] ===================================');
                let msg = {"type": "binder_recv_hook_ndk", "binder_func": funcs_to_hook[i].name, "backtrace": Thread.backtrace(this.context, Backtracer.FUZZY).map(DebugSymbol.fromAddress).join(","), "ctr": CALL_CTR, "calling_pid": calling_pid}
                send(JSON.stringify(msg));
            }
        })
        } catch {
            console.log("[*] failed to hook...")
        }
        console.log("[*] hooked: " + funcs_to_hook[i].name);
    }
}

/* ======================================================================================================================== *
 * getCallingPid                                                                                                            *                                                                                                               *
 * ======================================================================================================================== */

function get_getCallingPid(){
    var processes = Process.enumerateModules();
    for(let i = 0; i < processes.length; i++){
        var getCallingPid = processes[i].findExportByName("AIBinder_getCallingPid");
        if(getCallingPid !== null){
            console.log("[*] found AIBinder_getCallingPid at: " + getCallingPid + " in process: " + processes[i].name);
            return new NativeFunction(getCallingPid, 'int', []);
            break;
        }
    }
    console.log("[*] failed finding libbinder_ndk function, looking for libbinder one...")
    // _ZNK7android14IPCThreadState13getCallingPidEv
    for(let i = 0; i < processes.length; i++){
        var getIPCThreadStateSelf = processes[i].findExportByName("_ZN7android14IPCThreadState4selfEv")
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
 * main                                                                                                                     *                                                                                                               *
 * ======================================================================================================================== */

console.log("[*] hooked!");
var getCallingPid_Func = get_getCallingPid();
if(getCallingPid_Func === null){
    console.log("[!!] failed to find getCallingPid...");
    while(1){
    }
}


// hook libbinder.so functions
var parcel_extract_functions = get_parcel_extracting();
console.log("[*] found libbinder.so!readParcel* functions: ");
for(let i = 0; i < parcel_extract_functions.length; i++){
    console.log(" >>> " + parcel_extract_functions[i].name);
}
hook_parcel_extracting(parcel_extract_functions);

// hook libbinder_ndk.so functions
var ndk_funcs = get_parcel_extracting_ndk();
hook_parcel_extracting_ndk(ndk_funcs);

// finished, send setup_done to host
console.log("[*] finished setup");
send(JSON.stringify({"type": "setup_done"}))