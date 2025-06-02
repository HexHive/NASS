from typing import List
import ghidra.formats.gfilesystem.fileinfo
import java.lang


class FileAttributes(object):
    """
    A collection of FileAttribute values that describe a file.
    """

    EMPTY: ghidra.formats.gfilesystem.fileinfo.FileAttributes



    def __init__(self):
        """
        Creates a new / empty {@link FileAttributes} instance.
        """
        ...



    @overload
    def add(self, name: unicode, attributeValue: object) -> None:
        """
        Adds a custom named file attribute.
         <p>
         The value class should have a reasonable toString() that converts the value to something
         that is presentable to the user.
        @param name name of the attribute
        @param attributeValue value of the attribute
        """
        ...

    @overload
    def add(self, attributeType: ghidra.formats.gfilesystem.fileinfo.FileAttributeType, attributeValue: object) -> None:
        """
        Adds a typed file attribute value.
         <p>
         The value class needs to match {@link FileAttributeType#getValueType()}.
        @param attributeType {@link FileAttributeType} type of this value
        @param attributeValue value of attribute
        """
        ...

    @overload
    def add(self, attributeType: ghidra.formats.gfilesystem.fileinfo.FileAttributeType, displayName: unicode, attributeValue: object) -> None:
        """
        Adds a typed file attribute value.
         <p>
         The value class needs to match {@link FileAttributeType#getValueType()}.
        @param attributeType {@link FileAttributeType} type of this value
        @param displayName string used to label the value when displayed to the user
        @param attributeValue value of attribute
        @throws IllegalArgumentException if attributeValue does not match attributeType's 
         {@link FileAttributeType#getValueType()}.
        """
        ...

    def clone(self) -> ghidra.formats.gfilesystem.fileinfo.FileAttributes: ...

    def contains(self, attributeType: ghidra.formats.gfilesystem.fileinfo.FileAttributeType) -> bool:
        """
        Returns true if the specified attribute is present.
        @param attributeType attribute to query
        @return boolean true if present
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def get(self, attributeType: ghidra.formats.gfilesystem.fileinfo.FileAttributeType, valueClass: java.lang.Class, defaultValue: object) -> object:
        """
        Gets the value of the specified attribute.
        @param <T> expected class of the attribute value
        @param attributeType {@link FileAttributeType} enum type of attribute to search for
        @param valueClass java class of the value
        @param defaultValue value to return if attribute is not present
        @return value of requested attribute, or defaultValue if not present
        """
        ...

    def getAttributes(self) -> List[ghidra.formats.gfilesystem.fileinfo.FileAttribute]:
        """
        Return a list of all the attributes added to this instance.
        @return list of {@link FileAttribute}
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def of(__a0: List[ghidra.formats.gfilesystem.fileinfo.FileAttribute]) -> ghidra.formats.gfilesystem.fileinfo.FileAttributes: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def attributes(self) -> List[object]: ...