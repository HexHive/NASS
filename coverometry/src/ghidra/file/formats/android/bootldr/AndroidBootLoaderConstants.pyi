import ghidra.program.model.listing
import java.lang


class AndroidBootLoaderConstants(object):
    BOOTLDR_MAGIC: unicode = u'BOOTLDR!'
    BOOTLDR_MAGIC_SIZE: int = 8
    BOOTLDR_NAME: unicode = u'bootloader_images_header'
    IMG_INFO_NAME: unicode = u'img_info'
    IMG_INFO_NAME_LENGTH: int = 64



    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def isBootLoader(__a0: ghidra.program.model.listing.Program) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

