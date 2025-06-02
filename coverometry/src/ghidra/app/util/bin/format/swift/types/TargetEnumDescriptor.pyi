import ghidra.app.util.bin.format.swift.types
import ghidra.program.model.data
import java.lang


class TargetEnumDescriptor(ghidra.app.util.bin.format.swift.types.TargetTypeContextDescriptor):
    """
    Represents a Swift TargetEnumDescriptor structure
    """





    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new {@link TargetEnumDescriptor}
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

    def getNumEmptyCases(self) -> int:
        """
        Gets the number of empty cases in the enum
        @return The number of empty cases in the enum
        """
        ...

    def getNumPayloadCasesAndPayloadSizeOffset(self) -> int:
        """
        Gets the number of non-empty cases in the enum are in the low 24 bits; the offset of the 
         payload size in the metadata record in words, if any, is stored in the high 8 bits;
        @return The number of non-empty cases in the enum and the offset of the payload size
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
    def numEmptyCases(self) -> int: ...

    @property
    def numPayloadCasesAndPayloadSizeOffset(self) -> int: ...

    @property
    def structureName(self) -> unicode: ...