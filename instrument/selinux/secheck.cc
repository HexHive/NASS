#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <iostream>
#include <string>  // Include the string header


#include "selinux/android.h"
#include "selinux/label.h"


int main(int argc, char** argv){

	if(argc != 3){
		printf("usage: ./secheck [service name] [binder=1,hwbinder=2]\n");
		exit(-1);
	}
	std::string service_name = argv[1];
	int binder = atoi(argv[2]);
	if(binder != 1 && binder != 2){
		printf("binder has to be 1 or 2..\n");
		exit(-1);	
	}
	char* tctx = nullptr;
	if(binder == 1){
		if(selabel_lookup(selinux_android_service_context_handle(), &tctx, service_name.c_str(), SELABEL_CTX_ANDROID_SERVICE) != 0){
			printf("selabel_lookup failed...\n");
			exit(-1);
		}
	} else if (binder == 2){
		if(selabel_lookup(selinux_android_hw_service_context_handle(), &tctx, service_name.c_str(), 0) != 0){
			printf("selabel_lookup failed...\n");
			exit(-1);
		}
	}
	printf("service context: %s\n", tctx);
	const char* tclass;
	if(binder == 1){
		 tclass = "service_manager";
	} else if (binder == 2){
		 tclass = "hwservice_manager";
	}
	const char* perm = "find";
	const char* app_sid = "u:r:untrusted_app:s0";	
	int selinux_out = selinux_check_access(app_sid, tctx, tclass, perm, NULL);
	if(selinux_out != 0){
		printf("untrusted app does NOT have access...\n");
	} else {
		printf("access for untrusted app\n");
	}
}


