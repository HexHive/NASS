import ghidra.app.util.bin.format.swift.types
import ghidra.program.model.data
import java.lang


class TargetStructDescriptor(ghidra.app.util.bin.format.swift.types.TargetTypeContextDescriptor):
    """
    Represents a Swift TargetStructDescriptor structure
    """





    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new {@link TargetStructDescriptor}
        @param reader A {@link BinaryReader} positioned at the start of the structure
        @throws IOException if there was an IO-related problem creating the structure
        """
        ...



    def equals(self, __a0: object) -> bool: ...

    def getAccessFunctionPtr(self) -> int:
        """
        Gets the pointer to the metadata access function for this type
        @return The pointer to the metadata access function for this type
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getDescription(self) -> unicode: ...

    def getFieldOffsetVectorOffset(self) -> int:
        """
        Gets the offset of the field offset vector for this struct's stored properties in its 
         metadata, if any. 0 means there is no field offset vector.
        @return The offset of the field offset vector for this struct's stored properties in its 
           metadata, if any. 0 means there is no field offset vector.
        """
        ...

    def getFields(self) -> int:
        """
        Gets the pointer to the field descriptor for the type, if any
        @return The pointer to the field descriptor for the type, if any
        """
        ...

    def getFlags(self) -> int:
        """
        Gets the flags
        @return The flags
        """
        ...

    def getName(self) -> unicode:
        """
        Gets the name of the type
        @return The name of the type
        """
        ...

    def getNumFields(self) -> int:
        """
        Gets the number of stored properties in the struct. If there is a field offset vector, 
         this is its length.
        @return The number of stored properties in the struct. If there is a field offset vector, 
           this is its length.
        """
        ...

    def getParent(self) -> int:
        """
        Gets the parent's relative offset
        @return The parent's relative offset
        """
        ...

    def getStructureName(self) -> unicode: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toDataType(self) -> ghidra.program.model.data.DataType: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def description(self) -> unicode: ...

    @property
    def fieldOffsetVectorOffset(self) -> int: ...

    @property
    def numFields(self) -> int: ...

    @property
    def structureName(self) -> unicode: ...