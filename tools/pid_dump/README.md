# Pid Dumper

Compile: 
`gcc -fPIC -shared pid_dump.c -o pid_dump.so`

Usage:
`LD_PRELOAD=./pid_dump.so ./binder_caller`

Why:
Call a binder interface, get the pid and be able to figure out with getCallerPid if this is a request sent by us or by some other client.
Mainly used at the moment because I haven't yet implemented my own binder calling library and the existing ones (bdsm and service) don't 
log their own pid.