# Device specific binaries 

Structure: 
```
{device_id}/
  lib/       # relevant libraries
  fuzzer      # fuzzer binary
  example_service/ # example service and client
```

Download necessary libraries from the device:
`make {device_id}`

## Add new target

```
+ .PHONY ... [device_id]
+ [device_id]: DEVICE=[device_id]
+ [device_id]: download ## download librarief for [device_id] (...)
```
