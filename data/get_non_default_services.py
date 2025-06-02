import sys
import os
base_path = os.path.dirname(__file__)
sys.path.append(os.path.join(base_path, ".."))

import adb

import service.service as service

def get_non_default_services(device_id):
    default_services = open(os.path.join(base_path, "emulator_services.txt")).read().split("\n")
    device_services = adb.get_services(device_id)
    int_services = set(device_services).difference(set(default_services))
    return int_services

def get_default_services(device_id):
    default_services = open(os.path.join(base_path, "emulator_services.txt")).read().split("\n")
    device_services = adb.get_services(device_id)
    int_services = set(device_services).intersection(set(default_services)) 
    return int_services


if __name__ == "__main__":
    device_id = sys.argv[1]
    int_services = get_non_default_services(device_id)
    #print("\n".join(int_services))
