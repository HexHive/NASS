# Instrument 

## hook.py & interface.py

interact with the services, hook them and enumerate the interfaces.

## hook.js

Hooks all android::parcel::read* and checkInterface functions. 
This way we can figure out the onTransact function for a service and also understand what kindof data the service is expecting.

Test hooking of services: 

`frida -U -p $(pid of target service) -l instrument/hook.js`

### 