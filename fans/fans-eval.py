import os
import time

RUNS = 2

start_time = time.time()
os.system(f'echo > error.txt')
for i in range(0, RUNS):
    run_name = f'eval_6hr{i+1}'
    cmd = f'python3 fans-run.py {run_name} >> error.txt'
    os.system(cmd)

end_time = time.time()
print(f'finished in {end_time - start_time}s')