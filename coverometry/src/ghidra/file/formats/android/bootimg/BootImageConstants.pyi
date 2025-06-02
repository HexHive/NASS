import java.lang


class BootImageConstants(object):
    BOOT_ARGS_SIZE: int = 512
    BOOT_EXTRA_ARGS_SIZE: int = 1024
    BOOT_MAGIC: unicode = u'ANDROID!'
    BOOT_MAGIC_SIZE: int = 8
    BOOT_NAME_SIZE: int = 16
    DTB: unicode = u'dtb'
    HEADER_VERSION_OFFSET: int = 40
    ID_SIZE: int = 8
    KERNEL: unicode = u'kernel'
    RAMDISK: unicode = u'ramdisk'
    SECOND_STAGE: unicode = u'second stage'
    V3_HEADER_SIZE: int = 4096
    V3_PAGE_SIZE: int = 4096
    V4_HEADER_SIZE: int = 4096
    V4_PAGE_SIZE: int = 4096
    VENDOR_BOOT_ARGS_SIZE: int = 2048
    VENDOR_BOOT_MAGIC: unicode = u'VNDRBOOT'
    VENDOR_BOOT_MAGIC_SIZE: int = 8
    VENDOR_BOOT_NAME_SIZE: int = 16
    VENDOR_RAMDISK_NAME_SIZE: int = 32
    VENDOR_RAMDISK_TABLE_ENTRY_BOARD_ID_SIZE: int = 16
    VENDOR_RAMDISK_TYPE_DLKM: int = 3
    VENDOR_RAMDISK_TYPE_NONE: int = 0
    VENDOR_RAMDISK_TYPE_PLATFORM: int = 1
    VENDOR_RAMDISK_TYPE_RECOVERY: int = 2



    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

