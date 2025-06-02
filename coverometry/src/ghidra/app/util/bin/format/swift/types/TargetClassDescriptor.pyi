import ghidra.app.util.bin.format.swift.types
import ghidra.program.model.data
import java.lang


class TargetClassDescriptor(ghidra.app.util.bin.format.swift.types.TargetTypeContextDescriptor):
    """
    Represents a Swift TargetClassDescriptor structure
    """





    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new {@link TargetClassDescriptor}
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

    def getMetadataNegativeSizeInWords(self) -> int:
        """
        If this descriptor does not have a resilient superclass, this is the negative size of 
         metadata objects of this class (in words). If this descriptor has a resilient superclass, 
         this is a reference to a cache holding the metadata's extents.
        @return The negative size of metadata objects of this class (in words) or a reference to a 
           cache holding the metadata's extents
        """
        ...

    def getMetadataPositiveSizeInWords(self) -> int:
        """
        If this descriptor does not have a resilient superclass, this is the positive size of 
         metadata objects of this class (in words). Otherwise, these flags are used to do things like 
         indicate the presence of an Objective-C resilient class stub.
        @return The positive size of metadata objects of this class (in words) or flags used to do
           things like indicate the presence of an Objective-C resilient class stub.
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
        Gets the number of stored properties in the class, not including its superclasses. If there 
         is a field offset vector, this is its length.
        @return The number of stored properties in the class, not including its superclasses. 
           If there is a field offset vector, this is its length.
        """
        ...

    def getNumImmediateMembers(self) -> int:
        """
        Gets the number of additional members added by this class to the class metadata
        @return The number of additional members added by this class to the class metadata
        """
        ...

    def getParent(self) -> int:
        """
        Gets the parent's relative offset
        @return The parent's relative offset
        """
        ...

    def getStructureName(self) -> unicode: ...

    def getSuperclassType(self) -> int:
        """
        Gets the type of the superclass, expressed as a mangled type name that can refer to the 
         generic arguments of the subclass type
        @return The type of the superclass, expressed as a mangled type name that can refer to the 
           generic arguments of the subclass type
        """
        ...

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
    def metadataNegativeSizeInWords(self) -> int: ...

    @property
    def metadataPositiveSizeInWords(self) -> int: ...

    @property
    def numFields(self) -> int: ...

    @property
    def numImmediateMembers(self) -> int: ...

    @property
    def structureName(self) -> unicode: ...

    @property
    def superclassType(self) -> int: ...