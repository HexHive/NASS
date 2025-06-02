import sys
import os
import argparse

BASE_DIR = os.path.dirname(__file__)
sys.path.append(os.path.join(BASE_DIR, "..", ".."))

DEVICE = os.path.join(BASE_DIR, "..", "..", "device")

import adb
import service.service as service
import data.database as database

binder_db = database.open_db()

SELINUX_FOLDER = '/data/local/tmp/selinux'
SECHECK_PHONE = os.path.join(SELINUX_FOLDER, 'secheck')

def check_service(s, device_id, hwbinder=False):
    if hwbinder:
        out, err = adb.execute_privileged_command(f'{SECHECK_PHONE} {s} 2', device_id=device_id)
    else:
        out, err = adb.execute_privileged_command(f'{SECHECK_PHONE} {s} 1', device_id=device_id)
    out = out.decode()
    service_context = ":".join(out.split("\n")[0].split(":")[1:]).strip(" ")
    if 'access for untrusted app' in out:
        return service_context, True
    else:
        return service_context, False

def enumerate_selinux(device_id, hwbinder=False):
    adb.execute_privileged_command(f'mkdir -p {SELINUX_FOLDER}', device_id=device_id)
    secheck_local = os.path.join(DEVICE, device_id, 'secheck')
    if not os.path.exists(secheck_local):
        print(f'secheck does not exist!')
        return
    adb.push_privileged(secheck_local, SELINUX_FOLDER, device_id=device_id)
   
    if hwbinder:
        services = adb.get_hwbinder_services(device_id)
    else:
        services = adb.get_services(device_id)
    s2r = {}
    for s in services:
        service_context, app_reachable = check_service(s, device_id, hwbinder=hwbinder)
        if app_reachable:
            print(f'{s}({service_context}) accessable for app')
            s2r[s] = True
        else:
            print(f'{s}({service_context}) NOT accessable for app')
            s2r[s] = False
        database.insert_apphandle(binder_db, s, device_id, s2r[s], service_context)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=f'enumerate selinux on device')
    parser.add_argument("-d", "--device",  type=str, required=True, help="Device")
    parser.add_argument("-s", "--service",  type=str, required=False, help="Service")
    parser.add_argument("--hwbinder", default=False, required=False, action="store_true", help="do hwbinder")
    args = parser.parse_args()
    if args.device not in adb.get_device_ids():
        print(f'{args.device} not connected!')
        exit(-1)
    if args.service is not None:
        selinux_cts, accessible = check_service(args.service, args.device, args.hwbinder)
        print(f'{args.service}: accessible: {accessible}')
    else: 
        enumerate_selinux(args.device, args.hwbinder)

