import json
import os
import threading
import frida
import argparse
import os
import logging
import traceback
import sys
from datetime import datetime
import time
import json
import tempfile

BASE_DIR: str = os.path.dirname(__file__)
sys.path.append(os.path.join(BASE_DIR, ".."))

import adb
from config import FANS_PIXEL_2_XL, IS_EMULATOR


print('extract the services targeted by FANS')
print('and get all services that run standalone')
print('remove 32 bit services')
print(20*'=')

svc_info_path = 'workdir/interface-model-extractor/model/service'

libminijail_services = ["media.extractor", "media.extractor.update"]

fans_services = set()



for svc in os.listdir(svc_info_path):
    i = json.load(open(os.path.join(svc_info_path, svc)))
    for trans in i:
        fans_services.add(i[trans]["serviceName"])

print('\n'.join(list(fans_services)))

standalone_services = []

for s in fans_services:
    s_pid = adb.get_service_pid(s, device_id=FANS_PIXEL_2_XL[0])
    if s_pid is None:
        print(f'no pid for {s}')
        continue
    out, err = adb.execute_privileged_command(
        f"ps -A | grep {s_pid}", device_id=FANS_PIXEL_2_XL[0]
    )
    if b"system_server" in out:
        print(f"{s} in system server")
        continue
    adb.execute_privileged_command(f'cp /proc/{s_pid}/exe /data/local/tmp/wow', 
                                   device_id=FANS_PIXEL_2_XL[0])
    out, err = adb.execute_privileged_command(f'file /data/local/tmp/wow', 
                                              device_id=FANS_PIXEL_2_XL[0])
    if b"32-bit" in out:
        print(f'{s} is 32 bit')
        continue
    if s in libminijail_services:
        print(f'{s} has libminijail')
        continue
    standalone_services.append(s)

print(20*"=")
print('\n'.join(standalone_services))

open('fans_standalone_services.txt', 'w+').write('\n'.join(standalone_services))

