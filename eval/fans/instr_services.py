import os
import sys
BASE_DIR: str = os.path.dirname(__file__)

sys.path.append(os.path.join(BASE_DIR, "..", ".."))

from config import META_TARGET, IS_EMULATOR, AARCH64_EMU_28, AARCH64_EMU_34
import emulator.emulator as emulator


if IS_EMULATOR:
    d = "emulator-5554"
    emulator.reset(d)
else:
    d = sys.argv[1]

if META_TARGET == AARCH64_EMU_28:
    services_file = os.path.join(BASE_DIR, './fans_eval_services.txt')

services = open(services_file).read().split("\n")[:-1]

for s in services:
    print(f'python3 {BASE_DIR}/../../instrument/interface.py -s {s} -d {d}')
    os.system(f'python3 {BASE_DIR}/../../instrument/interface.py -s {s} -d {d}')

