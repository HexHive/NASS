import sys
import os

BASE_PATH = os.path.dirname(__file__)

sys.path.append(os.path.join(BASE_PATH, "..", ".."))
import emulator.emulator as emulator

emulator.full_reset(sys.argv[1])
