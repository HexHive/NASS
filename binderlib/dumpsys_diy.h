#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>
#include <stdio.h>
#include <iostream>
#include <dirent.h>
#include <cstring>
#include <string>
#include <cstdio>

using namespace android;

unsigned int get_node(pid_t pid){
    char path[256];
    sprintf(path, "/sys/kernel/debug/binder/proc/%d", pid);
    //printf("own pid path: %s \n", path);
    FILE* file = fopen(path, "r");
    if (file == nullptr) {
        //printf("failed to topen filepath\n");
        return -1;
    }

    char buffer[1024];
    int ctr = 0;
    int node_number = -1;
    while (fgets(buffer, sizeof(buffer), file)) {
        if (sscanf(buffer, "%*[^n]node %d", &node_number) == 1) {
            //printf("Node number: %d\n", node_number);
            if(ctr == 1){
                // the reference is alway second
                break;
            } else {
                ctr++;
            }
        } 
    }
    fclose(file);
    return node_number;
}

bool is_service(char* file_path, pid_t own_pid, int node_number){
    char start[0x100];
    sprintf(start, "node %d:", node_number);
    //printf("start: %s\n", start);
    FILE* file = fopen(file_path, "r");
    if (file == nullptr) {
        //printf("failed to topen filepath\n");
        return -1;
    }

    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), file)) {
        if (strstr(buffer, start) != NULL) {
            //printf("Found potential candiate: %s\n", buffer);
            char* proc_position = strstr(buffer, "proc");
            if (proc_position == NULL) {
                //printf("No 'proc' string found in the line.\n");
                return false;
            }

            // Move past the "proc" word to the numbers
            proc_position += strlen("proc");

            int pid;
            char* p = proc_position;
            
            // Scan through the numbers after "proc"
            while (sscanf(p, "%d", &pid) == 1) {
                // Check if the current pid matches own_pid
                if (pid == own_pid) {
                    //printf("Found pid %d after 'proc'\n", own_pid);
                    return true;
                }

                // Move pointer to the next number
                // Skip current number by finding the next space or digit
                while (*p && (*p == ' ' || (*p >= '0' && *p <= '9'))) {
                    p++;
                }
            }

            //printf("pid %d not found after 'proc'\n", own_pid);
                } 
            }
    fclose(file);
    return false;
}

pid_t get_service_pid(pid_t own_pid, int node_number){
    DIR* dir = opendir("/sys/kernel/debug/binder/proc/");
    if (dir == NULL){
        printf("failed to open /sys/kernel/debug/binder/proc/\n");
        return -1;
    }
    struct dirent* entry;
    pid_t curr_pid;
    char file_path[0x100];
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type == DT_REG) {  // Only process regular files
            sscanf(entry->d_name, "%d", &curr_pid);
            //printf("processing pid: %d\n", curr_pid);
            if(curr_pid == own_pid){
                continue;
            }
            sprintf(file_path, "/sys/kernel/debug/binder/proc/%d", curr_pid);
            if(is_service(file_path, own_pid, node_number)){
                return curr_pid;
            }
        }
    }
    return -1;
}

pid_t do_get_service_pid(){
    // only works if there is only one service handle opened!
    pid_t own_pid = getpid();
    int node_number = get_node(own_pid);
    if(node_number == -1){
        printf("failed to find node number...");
        return EXIT_FAILURE;
    }
    pid_t service_pid = get_service_pid(own_pid, node_number);
    return service_pid;
}

