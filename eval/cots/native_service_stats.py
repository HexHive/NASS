import sqlite3
import json
import sys
import os
from collections import Counter, defaultdict

BASE_DIR = os.path.dirname(__file__)

sys.path.append(os.path.join(BASE_DIR, "..", ".."))
import data.get_non_default_services as non_default
import instrument.selinux.secheck as secheck
import adb
"""
for the eval devices get statistics on native services
native services
prop. native services (run proprietary code)
hal native services (services with access to kernel)
"""
db = os.path.join(BASE_DIR, "binder_eval.db")
connection = sqlite3.connect(db)
cursor = connection.cursor()
def single_select(query):
    out = []
    cursor.execute(query)
    rows = cursor.fetchall()
    for row in rows:
        out.append(row[0])
    return out

def is_native(s, d):
    s_pid = adb.get_service_pid(s, d)
    if s_pid is None:
        return None
    out, _ = adb.execute_privileged_command(f'cat /proc/{s_pid}/maps', 
                                            device_id=d)
    return not b"libandroid_runtime" in out

def has_vendor_comp(s,d):
    s_pid = adb.get_service_pid(s, d)
    if s_pid is None:
        return None 
    out, err = adb.execute_privileged_command(
            f"ps -A | grep {s_pid}", device_id=d
        )
    #if b"system_server" in out:
        #print(f'{s} in system server')
        #return False 
    out, _ = adb.execute_privileged_command(f'cat /proc/{s_pid}/maps', 
                                            device_id=d) 
    return b"/vendor/" in out

devices = [
    'RZCX312P76A',
    'a497c295',
    'bai7gujvtchqeaus',
    '109443739F105084',
    '47030DLAQ0012N'
]

d2name = {
    'RZCX312P76A': "Stwentythree",
    'a497c295': "oneplustwelve",
    'bai7gujvtchqeaus': "redminotethirteen",
    '109443739F105084': "transsionpovaprofive",
    '47030DLAQ0012N': "pixeleight"

}

d2service = {}
d2native_service = {}
d2prop_native_service = {}
d2prop_native_service_2 = {}
d2framework_native_service = defaultdict(list)
d2aosp_native_service_with_prop = defaultdict(list)
d2hal_native_service = defaultdict(list)
d2prop_framew_ns = {}
d2prop_hal_ns = {}
d2prop_framew_ns_2 = {}
d2prop_hal_ns_2 = {}

d2aosp_native_service = defaultdict(list)

d2non_default = {}
d2default = {}

d2all = {}

for d in devices:
    d2all[d] = adb.get_services(device_id=d)
    d2service[d] = single_select(
        f'select service_name from service where device="{d}" and onTransact_bin != "";'
    )
    d2native_service[d] = single_select(
        f'select service_name from service where device="{d}" and onTransact_bin\
             not LIKE "%libandroid%" and onTransact_bin != "";'
    )
    d2non_default[d] = non_default.get_non_default_services(d)
    d2default[d] = non_default.get_default_services(d)
    adb.execute_privileged_command('setenforce 1', device_id=d)
    # dummy check for services where enumeration did not work

print("starting")

for d in d2all:
    for s in d2all[d]:
        print('isnative?', d,s)
        if s not in d2service[d] and s not in d2native_service[d]:
            d2service[d].append(s)
            isn = is_native(s, d)
            if isn is None:
                continue
            if isn:
                d2native_service[d].append(s)

print(0)            
all = []
for d, s in d2native_service.items():
    for svc in s:
        print('checking HAL', d, svc)
        ctx, app_reachable = secheck.check_service(svc, d)
        if app_reachable:
            d2framework_native_service[d].append(svc)
        else:
            d2hal_native_service[d].append(svc)
    d2prop_native_service[d] = list(set(d2native_service[d]).intersection(d2non_default[d]))
    d2aosp_native_service[d] = list(set(d2native_service[d]).intersection(d2default[d]))
    all += d2prop_native_service[d]

counts = Counter(all)


for d, s in d2prop_native_service.items():
    d2prop_hal_ns[d] = list(set(d2hal_native_service[d]).intersection(set(s)))
    d2prop_framew_ns[d] = list(set(d2framework_native_service[d]).intersection(set(s)))


for d, s in d2aosp_native_service.items():
    for svc in s:
        print('has_vendor?', d, svc)
        has_vd_comp = has_vendor_comp(svc, d)
        if has_vd_comp:
            d2aosp_native_service_with_prop[d].append(svc)

d2prop_native_nominijail = defaultdict(list)

def is_jailed(d,s):
    out,err = adb.execute_privileged_command(f'cat /proc/$(dumpsys --pid {s})/maps | grep minijail', device_id=d)
    if out != b"":
        return True
    return False

def shortcut(name, value):
    print(f'\\newcommand{{\\{name}}}{{{value}\\xspace}}')

overall_service = 0
overall_native_service = 0
overall_prop_1 = 0
overall_aosp = 0
prop_hal_1 = 0
prop_framew_1 = 0
aosp_with_prop = 0

print("finished")
print("")
print("")
print("results:")

for d in devices:
    nr_svc = len(d2service[d])
    nr_svc_nat = len(d2native_service[d])
    nr_svc_prop_1 = len(d2prop_native_service[d])
    nr_svc_prop_hal_1 = len(d2prop_hal_ns[d])
    nr_svc_prop_fw_1 = len(d2prop_framew_ns[d])
    nr_svc_aosp = len(d2aosp_native_service[d])
    nr_svc_aosp_with_prop = len(d2aosp_native_service_with_prop[d])
    overall_aosp += nr_svc_aosp
    overall_service += nr_svc
    overall_native_service += nr_svc_nat
    overall_prop_1 += nr_svc_prop_1
    prop_hal_1 += nr_svc_prop_hal_1
    prop_framew_1 += nr_svc_prop_fw_1
    aosp_with_prop += nr_svc_aosp_with_prop
    """
    shortcut(f'NrServices{d2name[d]}', nr_svc)
    shortcut(f'NrServicesNative{d2name[d]}', nr_svc_nat)
    shortcut(f'NrServicesNativeProp{d2name[d]}', nr_svc_prop_1)
    shortcut(f'NrServicesNativePropFramework{d2name[d]}', nr_svc_prop_fw_1)
    shortcut(f'NrServicesNativePropHAL{d2name[d]}', nr_svc_prop_hal_1)
    shortcut(f'NrServicesNativeAOSP{d2name[d]}', nr_svc_aosp)
    shortcut(f'NrServicesNativeAOSPWithProp{d2name[d]}', nr_svc_aosp_with_prop)
    """
    print(f'{d}: {nr_svc} services')
    print(f'{d}: {nr_svc_nat} native services')
    print(f'{d}: {nr_svc_prop_1} proprietary native services')
    print(f'{d}: {nr_svc_prop_fw_1} proprietary native framework services')
    print(f'{d}: {nr_svc_prop_hal_1} proprietary native HAL services')

overall_aosp = overall_native_service - overall_prop_1
"""
shortcut(f'NrServices', overall_service) 
shortcut(f'NrServicesNative', overall_native_service)
shortcut(f'NrServicesNativeProp', overall_prop_1)
shortcut(f'NrServicesNativePropFramework', prop_framew_1)
shortcut(f'NrServicesNativePropHAL', prop_hal_1)
shortcut(f'NrServicesNativeAOSP', overall_aosp)
shortcut(f'NrServicesNativeAOSPWithProp', aosp_with_prop)
shortcut(f'PercentageNativeProp', (overall_prop_1/overall_native_service)*100)
shortcut(f'PercentageNativeAospWithProp', (aosp_with_prop/overall_aosp)*100)
"""
print(f'overall services: {overall_service}')
print(f'overall native: {overall_native_service}')
print(f'overall proprietary native: {overall_prop_1}')
print(f'overall proprietary native framework: {prop_framew_1}')
print(f'overall proprietary native hal: {prop_hal_1}')
print(f'overall AOSP with proprietary components: {aosp_with_prop}')


