# Google Pixel BBinder Hook

on google pixel devices, for some reason BBinder::transact is inlined. 
Need to update the offset inside the `hook_onTransact_pixel.js`.

Code inside `_ZN7android14IPCThreadState14executeCommandEi`:
```
            else if ((uint)local_3b0 == 0x5f504e47) {
              uVar20 = (**(code **)(*plStack952 + 0x18))(plStack952);
            }
            else if ((uint)local_3b0 == 0x5f525043) {
              __android_log_print(5,0,"%s: disallowed because RPC is not enabled",
                                  "status_t android::BBinder::setRpcClientDebug(const Parcel &)");
              uVar20 = 0xffffffda;
            }
            else {
              if ((uint)local_3b0 == 0x5f535244) goto code_r0x00152964;
LAB_00151a30:
              uVar20 = (**(code **)(*plStack952 + 0x80)) // call to BBinder::transact
                                 (plStack952,(ulong)local_3b0 & 0xffffffff,&local_2d0,&local_350,
                                  local_3b0._4_4_);
```

hook instruction just before blr x8 (something like ldr [x8 + 0x80])

also might need to adjust this_arg register

```
        00159484 e0 03 17 aa     mov        this,x23
        00159488 e1 03 16 2a     mov        param_1,w22
```