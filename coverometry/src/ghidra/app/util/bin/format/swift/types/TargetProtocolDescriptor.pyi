import ghidra.app.util.bin.format.swift.types
import ghidra.program.model.data
import java.lang


class TargetProtocolDescriptor(ghidra.app.util.bin.format.swift.types.TargetContextDescriptor):
    """
    Represents a Swift TargetProtocolDescriptor structure
    """





    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new {@link TargetProtocolDescriptor}
        @param reader A {@link BinaryReader} positioned at the start of the structure
        @throws IOException if there was an IO-related problem creating the structure
        """
        ...



    def equals(self, __a0: object) -> bool: ...

    def getAssociatedTypeNames(self) -> int:
        """
        Gets the associated type names
        @return The associated type names
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getDescription(self) -> unicode: ...

    def getFlags(self) -> int:
        """
        Gets the flags
        @return The flags
        """
        ...

    def getName(self) -> unicode:
        """
        Gets the name of the protocol
        @return The name of the protocol
        """
        ...

    def getNumRequirements(self) -> int:
        """
        Gets the number of requirements in the protocol
        @return The number of requirements in the protocol
        """
        ...

    def getNumRequirementsInSignature(self) -> int:
        """
        Gets the number of generic requirements in the requirement signature of the protocol
        @return The number of generic requirements in the requirement signature of the protocol
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
    def associatedTypeNames(self) -> int: ...

    @property
    def description(self) -> unicode: ...

    @property
    def name(self) -> unicode: ...

    @property
    def numRequirements(self) -> int: ...

    @property
    def numRequirementsInSignature(self) -> int: ...

    @property
    def structureName(self) -> unicode: ...