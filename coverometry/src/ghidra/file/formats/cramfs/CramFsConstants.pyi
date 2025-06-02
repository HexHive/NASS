import java.lang


class CramFsConstants(object):
    BLOCK_POINTER_SIZE: int = 4
    CRAMFS_FLAG_EXT_BLOCK_POINTERS: int = 2048
    CRAMFS_GID_WIDTH: int = 8
    CRAMFS_MODE_WIDTH: int = 16
    CRAMFS_NAMELEN_WIDTH: int = 6
    CRAMFS_OFFSET_WIDTH: int = 26
    CRAMFS_SIZE_WIDTH: int = 24
    CRAMFS_UID_WIDTH: int = 16
    DEFAULT_BLOCK_SIZE: int = 4096
    HEADER_STRING_LENGTH: int = 16
    INODE_SIZE: int = 12
    MAGIC: int = 684539205
    ZLIB_MAGIC_SIZE: int = 2



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

