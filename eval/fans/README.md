# FANS Evaluation

## Figure 3: FANS, NASS Coverage Evaluation

The following script runs all required steps to reproduce the fuzzing campaign from Section 8.3 and generate coverage graphs (adjust runtime, #runs accordingly):

```
./run_eval.sh [run_name] 
```

The coverage graph pdfs can be found at `../run_out/[run_name]/`.

To run the script make sure to have the fuzzer compiled for the target `aarch64emu28` and have setup the emulator docker according to `<repo>/emulator`.

## Table 3: Ground Truth 

To reproduce table 3, run the script:
```
python3 ground_truth.py
```

