# Many Emulators

slow down in fuzzing at too many emulators -cores 2


# IPC Request Capturing

Script that hooks all non-default services and captures command ids seen for 
these commands.

```
python3 eval/ipc_capture.py -d [device_id] -t [time] -o [output_path]
```

Then run interaction scripts with the phone

## VTS

build vts: 
```
lunch aosp_arm64-trunk_staging-eng 
```

## DGIE COTS EVAL

https://docs.google.com/spreadsheets/d/1Ga8fM09vTSBniBejN8x0IyFhySq94cDHIm12gkCS7A0/edit?usp=sharing
