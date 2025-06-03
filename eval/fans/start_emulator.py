import sys
import os

BASE_PATH = os.path.dirname(__file__)

sys.path.append(os.path.join(BASE_PATH, "..", ".."))
import emluator.emulator as emulator

emulator.start_emulator(sys.argv[1])
