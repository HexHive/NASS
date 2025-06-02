#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>
#include <stdio.h>
#include <iostream>
#include <dirent.h>
#include <cstring>
#include <string>
#include <cstdio>

#include "dumpsys_diy.h"

using namespace android;

int main(int argc, char** argv){
    if(argc < 2){
        printf("usage ./dumpsys [servicename]");
        exit(-1);
    }
    sp < IServiceManager > sm = defaultServiceManager();
    if (!sm) {
        printf("failed to get service manager!");
        return EXIT_FAILURE;
    }
    char* service_name = argv[1];
    String16 name(service_name);
    sp < IBinder > service = sm->checkService(name);
    if (!service) {
        printf("failed to get service!");
        return EXIT_FAILURE;
    }
    pid_t service_pid = do_get_service_pid(); 
    printf("%d\n", service_pid);
}
