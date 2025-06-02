# COTS Evaluation

## Table 1, Numbers of Native Services

Enumerate number of services (including native services, HAL etc) on the devices. 
```
python3 native_service_stats.py
```

## Table 6, COTS Service Crashes

Run preprocessing, fuzzing, triage and display the results on a subset of services for a specific device:
```bash
./run-fuzz.sh [device_id]
``` 

Modify `FUZZ_TIME` in the script to adjust the time each service is fuzzed.

Run the fuzzing campaign on all native services:
```bash
./run-fuzz.sh [device_id] all
```

Note that native services in the system server are excluded due to stability issues. 

In general this script is not guaranteed to finish since devices may need a manual reboot/reset during the run.

## Table 7, COTS Service Compliance

The `cots_dgie_eval` folder contains the service binaries along with the offset to the entry point function for the COTS service compliance experiment.

The results of the manual analysis can be found here: 
`https://docs.google.com/spreadsheets/d/1Ga8fM09vTSBniBejN8x0IyFhySq94cDHIm12gkCS7A0/edit?usp=sharing`


