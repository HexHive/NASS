import ghidra.formats.gfilesystem.fileinfo
import java.lang


class FileAttribute(object):
    """
    A (type, type_display_string, value) tuple.
    """









    @overload
    @staticmethod
    def create(name: unicode, attributeValue: object) -> ghidra.formats.gfilesystem.fileinfo.FileAttribute:
        """
        Creates a new {@link FileAttribute} instance with an 
         {@link FileAttributeType#UNKNOWN_ATTRIBUTE} type and the specified display name.
        @param <T> type of the value
        @param name custom display name for the value
        @param attributeValue value (should be .toString()'able)
        @return new FileAttribute instance
        """
        ...

    @overload
    @staticmethod
    def create(attributeType: ghidra.formats.gfilesystem.fileinfo.FileAttributeType, attributeValue: object) -> ghidra.formats.gfilesystem.fileinfo.FileAttribute:
        """
        Creates a new {@link FileAttribute} instance with the specified type and value.
        @param <T> type of the value
        @param attributeType {@link FileAttributeType} type
        @param attributeValue value (should match the 
         type specified in {@link FileAttributeType#getValueType()})
        @return new FileAttribute instance
        """
        ...

    @overload
    @staticmethod
    def create(attributeType: ghidra.formats.gfilesystem.fileinfo.FileAttributeType, attributeDisplayName: unicode, attributeValue: object) -> ghidra.formats.gfilesystem.fileinfo.FileAttribute:
        """
        Creates a new {@link FileAttribute} instance with the specified type, display name and
         value.
        @param <T> type of the value
        @param attributeType {@link FileAttributeType} type
        @param attributeDisplayName display name of the type
        @param attributeValue value (should match the 
         type specified in {@link FileAttributeType#getValueType()})
        @return new FileAttribute instance
        """
        ...

    def equals(self, obj: object) -> bool: ...

    def getAttributeDisplayName(self) -> unicode:
        """
        Returns the display name of this instance.  This is usually derived from
         the {@link FileAttributeType#getDisplayName()}.
        @return string display name
        """
        ...

    def getAttributeType(self) -> ghidra.formats.gfilesystem.fileinfo.FileAttributeType:
        """
        Returns the {@link FileAttributeType} of this instance.
        @return {@link FileAttributeType}
        """
        ...

    def getAttributeValue(self) -> object:
        """
        Return the value.
        @return value
        """
        ...

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

    @property
    def attributeDisplayName(self) -> unicode: ...

    @property
    def attributeType(self) -> ghidra.formats.gfilesystem.fileinfo.FileAttributeType: ...

    @property
    def attributeValue(self) -> object: ...