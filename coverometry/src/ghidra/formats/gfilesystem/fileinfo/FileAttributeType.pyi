from typing import List
import ghidra.formats.gfilesystem.fileinfo
import java.lang
import java.util


class FileAttributeType(java.lang.Enum):
    ACCESSED_DATE_ATTR: ghidra.formats.gfilesystem.fileinfo.FileAttributeType = ACCESSED_DATE_ATTR
    COMMENT_ATTR: ghidra.formats.gfilesystem.fileinfo.FileAttributeType = COMMENT_ATTR
    COMPRESSED_SIZE_ATTR: ghidra.formats.gfilesystem.fileinfo.FileAttributeType = COMPRESSED_SIZE_ATTR
    CREATE_DATE_ATTR: ghidra.formats.gfilesystem.fileinfo.FileAttributeType = CREATE_DATE_ATTR
    FILE_TYPE_ATTR: ghidra.formats.gfilesystem.fileinfo.FileAttributeType = FILE_TYPE_ATTR
    FSRL_ATTR: ghidra.formats.gfilesystem.fileinfo.FileAttributeType = FSRL_ATTR
    GROUP_ID_ATTR: ghidra.formats.gfilesystem.fileinfo.FileAttributeType = GROUP_ID_ATTR
    GROUP_NAME_ATTR: ghidra.formats.gfilesystem.fileinfo.FileAttributeType = GROUP_NAME_ATTR
    HAS_GOOD_PASSWORD_ATTR: ghidra.formats.gfilesystem.fileinfo.FileAttributeType = HAS_GOOD_PASSWORD_ATTR
    IS_ENCRYPTED_ATTR: ghidra.formats.gfilesystem.fileinfo.FileAttributeType = IS_ENCRYPTED_ATTR
    MODIFIED_DATE_ATTR: ghidra.formats.gfilesystem.fileinfo.FileAttributeType = MODIFIED_DATE_ATTR
    NAME_ATTR: ghidra.formats.gfilesystem.fileinfo.FileAttributeType = NAME_ATTR
    PATH_ATTR: ghidra.formats.gfilesystem.fileinfo.FileAttributeType = PATH_ATTR
    PROJECT_FILE_ATTR: ghidra.formats.gfilesystem.fileinfo.FileAttributeType = PROJECT_FILE_ATTR
    SIZE_ATTR: ghidra.formats.gfilesystem.fileinfo.FileAttributeType = SIZE_ATTR
    SYMLINK_DEST_ATTR: ghidra.formats.gfilesystem.fileinfo.FileAttributeType = SYMLINK_DEST_ATTR
    UNIX_ACL_ATTR: ghidra.formats.gfilesystem.fileinfo.FileAttributeType = UNIX_ACL_ATTR
    UNKNOWN_ATTRIBUTE: ghidra.formats.gfilesystem.fileinfo.FileAttributeType = UNKNOWN_ATTRIBUTE
    USER_ID_ATTR: ghidra.formats.gfilesystem.fileinfo.FileAttributeType = USER_ID_ATTR
    USER_NAME_ATTR: ghidra.formats.gfilesystem.fileinfo.FileAttributeType = USER_NAME_ATTR







    @overload
    def compareTo(self, __a0: java.lang.Enum) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def describeConstable(self) -> java.util.Optional: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDeclaringClass(self) -> java.lang.Class: ...

    def getDisplayName(self) -> unicode: ...

    def getGroup(self) -> ghidra.formats.gfilesystem.fileinfo.FileAttributeTypeGroup: ...

    def getValueType(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def name(self) -> unicode: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def ordinal(self) -> int: ...

    def toString(self) -> unicode: ...

    @overload
    @staticmethod
    def valueOf(__a0: unicode) -> ghidra.formats.gfilesystem.fileinfo.FileAttributeType: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.formats.gfilesystem.fileinfo.FileAttributeType]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def displayName(self) -> unicode: ...

    @property
    def group(self) -> ghidra.formats.gfilesystem.fileinfo.FileAttributeTypeGroup: ...

    @property
    def valueType(self) -> java.lang.Class: ...