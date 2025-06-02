import os

BASE_DIR: str = os.path.dirname(__file__)

if "CUSTOM_DB" in os.environ:
    BINDER_DB = os.environ["CUSTOM_DB"]
else:
    BINDER_DB = os.path.join(
        BASE_DIR, "data", "binder.db"
    )  
TARGET_DIR = os.path.join(BASE_DIR, "targets")  # devices and services
DEVICE_DIR = os.path.join(BASE_DIR, "device")  # device specific binaries
TOOLS_DIR = os.path.join(BASE_DIR, "tools")
FRIDA_SERVER_DIR = os.path.join(TOOLS_DIR, "frida")
# NOTE: Please keep this stable for the duration of the project (reduce friction for collaborators)
FRIDA_VERSION = "16.5.6"

PREPOCESS_FUZZ_BACK = "back_fuzz_out_preprocess"
PREPOCESS_DIR_NAME = "preprocess"
PREPOCESS_CMDID_DIR = "cmd_ids"
PREPOCESS_ITERATION_DIR_PREFIX = "ie_"
PREPROCESS_FINAL_DIR = "final"
PREPROCESS_CRASHING_DIR = "crashing" # final preprocessed seeds that immediatly crash
PHASE_1_SEED_DIRNAME = "phase_1_seeds"
PHASE_2_SEED_DIRNAME = "phase_2_seeds"
DRCOV_DIRNAME = "drcov"

TRIAGE_NASS_DEDUP = "nass_deduplicated"
TRIAGE_FANS_DEDUP = "fans_deduplicated"

FUZZ_REBOOTS_TRACKER = "device.txt" # a file in which the orchestrator tracks when the device died 
FUZZ_TIMEOUTS_TRACKER = "timeouts.txt" # a file in which the orchestrator tracks when timeouts occur 
FUZZ_START_TIME = "start_time.txt" # a file where the orchestrator writes the fuzzing start time
FUZZ_END_TIME = "end_time.txt" # a file where the orchestrator writes the end times

# Colors
RED = "\033[0;31m"
YELLOW = "\033[0;33m"
GREEN = "\033[0;32m"
NC = "\033[0m"
BLUE = "\033[0;34m"  # Blue
PURPLE = "\033[0;35m"  # Purple
CYAN = "\033[0;36m"  # Cyan

LIBRARY_BLOCKLIST = (
    open(
        os.path.join(
            BASE_DIR, "fuzz", "instrumentation_ranges", "library_blocklist.txt"
        )
    )
    .read()
    .split("\n")
)

BINDER_FUNCS = {
    "readBool": ["readBool", "AParcel_readBool"],
    "readByte": ["readByte", "AParcel_readByte"],  # 1 byte
    "readChar": ["readChar", "AParcel_readChar"],  # 2 bytes
    "readInt32": [
        "readInt32",
        "readUint32",
        "readFloat",
        "AParcel_readFloat",
        "AParcel_readInt32",
        "AParcel_readUInt32",
    ],
    "readInt64": [
        "readInt64",
        "readUint64",
        "readDouble",
        "AParcel_readDouble",
        "AParcel_readInt64",
        "AParcel_readUInt64",
    ],
    "readCString": ["readCString"],
    "readString8": ["readString8", "readString8Inplace"],
    "readString16": [
        "readString16",
        "readString16Inplace",
        "AParcel_readString",
    ],
    "readUtf8FromUtf16": ["readUtf8FromUtf16"],
    "readStrongBinder": [
        "readStrongBinder",
        "readNullableStrongBinder",
        "AParcel_readStrongBinder",
    ], # strong binder type
    "readBoolVector": [
        "readBoolVector",
        "AParcel_readBoolArray"
    ], #vector of bools
    "readCharVector": [
        "readCharVector",
        "AParcel_readCharArray"
    ], #vector of int16
    "readInt32Vector" : [
        "readInt32Vector",
        "AParcel_readInt32Array",
        "readFloatVector",
        "AParcel_readFloatArray",
        "readUint32Vector",
        "AParcel_readUint32Array"
    ], #vector of int32
    "readInt64Vector" : [
        "readInt64Vector",
        "readUint64Vector",
        "readDoubleVector",
        "AParcel_readDoubleArray",
        "AParcel_readInt64Array",
        "AParcel_readUint64Array" 
    ], # vector of int64
    "readString16Vector": [
        "readString16Vector",
        "AParcel_readStringArray"
    ],
    "readUtf8VectorFromUtf16Vector": [
        "readUtf8VectorFromUtf16Vector"
    ],
    "readNativeHandle": ["readNativeHandle"],
    "readFileDescriptor": ["readFileDescriptor", "readUniqueFileDescriptor"],
    "readParcelFileDescriptor": [
        "readParcelFileDescriptor",
        "AParcel_readParcelFileDescriptor",
    ],
    "read": ["read", "readInplace"],
    "checkInterface": ["checkInterface"],
    "readByteArray": ["readByteVector", "AParcel_readByteArray"],
    "readInt32ParcebleSize": [],
    "readUnsafeTypedVector": ["readUnsafeTypedVector"]
}

# binder deserialization functions that may call other ones
BINDERFUNCSWRAPPER = [
    "readBoolVector",
    "readCharVector",
    "readInt32Vector",
    "readInt64Vector",
    "readString16Vector",
    "readUtf8VectorFromUtf16Vector",
    "readNativeHandle",
    "readByteArray",
    "readFileDescriptor",
    "readParcelFileDescriptor",
    "readUtf8FromUtf16" 
]

TMPFS = "/data/local/tmp/tmpfs/"
SHMEM = os.path.join(TMPFS, ".shmem")
FRIDA_MAP_SIZE = 0x8000

# Services that in the past have FU**** the device
PAIN = {
    "3C161FDJHS0651": [
        "android.hardware.weaver.IWeaver/default",
        "android.hardware.boot.IBootControl/default",
    ],
    "47030DLAQ0012N": [
        "android.hardware.weaver.IWeaver/default",
        "android.hardware.boot.IBootControl/default",
    ],
    #"710KPZK0476701": ["vold"],
    #"712KPBF1235565": ["vold"],
}

SCUFFED_SERVICES = ["manager"]

SKIP_SERVICES = {
    "R58Y105KVBA": [
        "manager",
        "vold"
    ],
    "RKXK7HDIRWGMDYWO": [
        "manager",
        "vold",
        "media.extractor",
        "media.resource_observer",
        "media.player", #32bit
        "drm.drmManager", #32bit
    ],
    "089092526K000893": [
        "manager",
        "vold",
        "media.extractor",
        "media.resource_observer",
        "media.player", #32bit
        "drm.drmManager", #32bit
    ],
    "bai7gujvtchqeaus": [
        "manager",
        "vold",
        "media.extractor",
        "drm.drmManager", #32bit
        "media.resource_observer", # 32bit
        "media.resource_manager", #32bit
        "media.player", #32bit
    ],
    "RZCX312P76A": [
        "manager",
        "vold",
        "vendor.qti.data.txpwrservice.ITxPwrService/default",
        "drm.drmManager",
        "vendor.perfservice",
        "media.extractor",
        "apexservice",
        "dnsresolver",#???
    ],
    "ONFYMRTKROLBRSHA": [
        "manager",
        "android.hardware.boot.IBootControl/default",
        "android.hardware.weaver.IWeaver/default",
        "vold",
        "miuiboosterservice",
        "SurfaceFlinger",
        "SurfaceFlingerAIDL",
    ],
    "3C161FDJHS0651": [
        "manager", 
        "vold",
        "SurfaceFlinger",
        "SurfaceFlingerAIDL" ,
        "android.hardware.weaver.IWeaver/default",
        "android.hardware.boot.IBootControl/default",
        "android.hardware.secure_element.ISecureElement/SIM2",
        "android.hardware.secure_element.ISecureElement/SIM1"
    ], 
    "47030DLAQ0012N": [
        "manager", 
        "vold",
        "SurfaceFlinger",
        "SurfaceFlingerAIDL" ,
        "android.hardware.weaver.IWeaver/default",
        "android.hardware.boot.IBootControl/default",
        "android.hardware.secure_element.ISecureElement/SIM2",
        "android.hardware.secure_element.ISecureElement/SIM1",
        "dexopt_chroot_setup", # fucked
        "android.hardware.usb.gadget.IUsbGadget/default", #adb gone
        "apexservice", # hanging
        "dnsresolver", #???
        "android.hardware.usb.IUsb/default",  # adb getting messed up
        "android.hardware.security.keymint.IKeyMintDevice/default", # device destroyed after here
        "android.hardware.cas.IMediaCasService/default", # rpc exception,
        "android.hardware.security.keymint.IRemotelyProvisionedComponent/default", #rust :(
        "android.hardware.graphics.composer3.IComposer/default",
    ],
    "48161FDJHS0DQ0": [
        "manager",
        "vold",
        "android.hardware.weaver.IWeaver/default",
        "media.extractor",
        "android.hardware.boot.IBootControl/default", #kills device
        "android.hardware.media.c2.IComponentStore/default1",
        "android.hardware.media.c2.IComponentStore/default",
        "android.hardware.usb.gadget.IUsbGadget/default", # adb gone
    ],
    "a497c295": [
        "android.hardware.radio.data.IRadioData/slot1", #minijail
        "android.hardware.radio.data.IRadioData/slot2", #minijail
        "android.hardware.radio.messaging.IRadioMessaging/slot1", #minijail
        "android.hardware.radio.messaging.IRadioMessaging/slot2", #minijail
        "vendor.oplus.hardware.ims.IImsStable/OplusImsRadio0", #minijail
        "android.hardware.radio.modem.IRadioModem/slot1", #minijail
        "android.hardware.radio.modem.IRadioModem/slot2", #minijail
        "android.hardware.radio.network.IRadioNetwork/slot1", #minijail
        "android.hardware.radio.network.IRadioNetwork/slot2", #minijail
        "android.hardware.radio.sim.IRadioSim/slot1", #minijail
        "android.hardware.radio.sim.IRadioSim/slot2", #minijail
        "android.hardware.radio.voice.IRadioVoice/slot1", #minijail
        "android.hardware.radio.voice.IRadioVoice/slot2", #minijail
        "vendor.perfservice", # signal 31
        "android.hardware.radio.config.IRadioConfig/default", # minijail
        "android.hardware.dumpstate.IDumpstateDevice/default", # hanging
        "cotaservice", #unable to find android linker
        "drm.drmManager", #32bit
        "media.extractor", #libminjail
        "vendor.oplus.hardware.appradioaidl.IAppRadioStable/OplusAppRadio0", #libminijail
        "vendor.oplus.hardware.appradioaidl.IAppRadioStable/OplusAppRadio1", #libminijail
        "vendor.oplus.hardware.radio.IRadioStable/OplusRadio0", #libminjail
        "vendor.oplus.hardware.radio.IRadioStable/OplusRadio1", #libminjail
        "vendor.oplus.hardware.ims.IImsStable/OplusImsRadio0", #libminijail
        "vendor.oplus.hardware.ims.IImsStable/OplusImsRadio1", #libminijail
        "vendor.qti.hardware.data.connectionfactory.IFactory/slot0", #libminijail
        "vendor.qti.hardware.data.connectionfactory.IFactory/slot1", #libminijail
        "vendor.qti.hardware.qxr.IQXRCamService/default", #fucked
        "vendor.qti.hardware.qxr.IQXRModService/default", #fucked
        "vendor.qti.hardware.qxr.IQXRSplitService/default", #fucked
        "vendor.qti.hardware.radio.qcrilhook.IQtiOemHook/oemhook0", #minijail
        "vendor.qti.hardware.radio.qcrilhook.IQtiOemHook/oemhook1", #minijail
        "vendor.qti.hardware.qxr.IQXRAudioService/default", #minijail
        "vendor.qti.hardware.qxr.IQXRCoreService/default", #minijail
        "vendor.qti.hardware.radio.am.IQcRilAudio/slot1", #minijail
        "vendor.qti.hardware.radio.am.IQcRilAudio/slot2", #minijail
        "vendor.qti.hardware.radio.ims.IImsRadio/imsradio1", #minijail
        "vendor.qti.hardware.radio.ims.IImsRadio/imsradio2", #minijail
        "vendor.qti.hardware.radio.internal.deviceinfo.IDeviceInfo/deviceinfo", #minijail
        "vendor.qti.hardware.radio.qtiradio.IQtiRadioStable/slot1", #minijail
        "vendor.qti.hardware.radio.qtiradio.IQtiRadioStable/slot2", #minijail
        "vendor.qti.hardware.radio.ims.IImsRadio/imsradio0", #minijail
        "vendor.qti.hardware.radio.qtiradioconfig.IQtiRadioConfig/default", #minijail
    ]
}

FANS_PIXEL_2_XL = ["710KPZK0476701", "712KPBF1235565"]
CUSTOM_DUMPSYS_PATH = "/data/local/tmp/dumpsys/dumpsys"
SEEDSDRCOV = "seeds"

PHASE_1_BACKUP_DATA = "phase_1_data"

META_TARGET = None
NEED_CUSTOM_DUMPSYS = False
IS_EMULATOR = False

AARCH64_EMU_28 = 'aarch64emu28'
IS_ANDROID_28 = False

AARCH64_EMU_34 = 'aarch64emu34'

X86_EMU_28 = 'x86emu28'

META2DOCKERIMAGE = {
    AARCH64_EMU_28: 'emu',
    AARCH64_EMU_34: 'emu34'
}

if 'META_TARGET' in os.environ:
    META_TARGET = os.environ['META_TARGET']
    if META_TARGET == AARCH64_EMU_28:
        IS_EMULATOR = True
        IS_ANDROID_28 = True
        NEED_CUSTOM_DUMPSYS = True
    if META_TARGET == AARCH64_EMU_34:
        IS_EMULATOR = True
        IS_ANDROID_28 = False
        NEED_CUSTOM_DUMPSYS = False
    if META_TARGET == X86_EMU_28:
        IS_ANDROID_28 = True
        NEED_CUSTOM_DUMPSYS = True
        IS_EMULATOR = False

BINDER_KNOWN_CMDS = [
    0x5f434d44
]

FANS_EVAL_TIME = 60 * 60 * 24
FANS_EVAL_RUNS = 5
FANS_NOVARMAP_FILE = "novarmap_fans.txt"

if "FUZZ_COV_RATE_PROP" in os.environ:
    FUZZ_COV_RATE_PROP = int(os.environ["FUZZ_COV_RATE_PROP"])
else:
    FUZZ_COV_RATE_PROP = 5

if "FUZZ_COV_RATE_TIME" in os.environ:
    FUZZ_COV_RATE_TIME = int(os.environ["FUZZ_COV_RATE_TIME"])
else:
    FUZZ_COV_RATE_TIME = 2 * 60

if "FUZZ_COV_RATE_MAX_TIME" in os.environ:
    FUZZ_COV_RATE_MAX_TIME = int(os.environ["FUZZ_COV_RATE_MAX_TIME"])
else:
    FUZZ_COV_RATE_MAX_TIME = 20 * 60

