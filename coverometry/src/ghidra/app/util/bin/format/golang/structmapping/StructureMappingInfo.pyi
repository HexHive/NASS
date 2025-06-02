from typing import List
import ghidra.app.util.bin.format.golang.structmapping
import ghidra.app.util.bin.format.golang.structmapping.StructureMappingInfo
import ghidra.program.model.data
import java.lang
import java.lang.reflect


class StructureMappingInfo(object):
    """
    Contains immutable information about a structure mapped class needed to deserialize
     a new object from the data found in a Ghidra program.
    """









    def assignContextFieldValues(self, context: ghidra.app.util.bin.format.golang.structmapping.StructureContext) -> None:
        """
        Initializes any {@link ContextField} fields in a new structure instance.
        @param context {@link StructureContext}
        @throws IOException if error assigning values to context fields in the structure mapped
         instance
        """
        ...

    def createStructureDataType(self, context: ghidra.app.util.bin.format.golang.structmapping.StructureContext) -> ghidra.program.model.data.Structure:
        """
        Creates a new customized {@link Structure structure data type} for a variable length
         structure mapped class.
        @param context {@link StructureContext} of a variable length structure mapped instance
        @return new {@link Structure structure data type} with a name that encodes the size 
         information of the variable length fields
        @throws IOException if error creating the Ghidra data type
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def fromClass(targetClass: java.lang.Class, structDataType: ghidra.program.model.data.Structure) -> ghidra.app.util.bin.format.golang.structmapping.StructureMappingInfo:
        """
        Returns the mapping info for a class, using annotations found in that class.
        @param <T> structure mapped class
        @param targetClass structure mapped class
        @param structDataType Ghidra {@link DataType} that defines the binary layout of the mapped
         fields of the class, or null if this is a self-reading {@link StructureReader} class
        @return new {@link StructureMappingInfo} for the specified class
        @throws IllegalArgumentException if targetClass isn't tagged as a structure mapped class
        """
        ...

    def getAfterMethods(self) -> List[java.lang.reflect.Method]: ...

    def getClass(self) -> java.lang.Class: ...

    def getDescription(self) -> unicode: ...

    def getFields(self) -> List[ghidra.app.util.bin.format.golang.structmapping.FieldMappingInfo]: ...

    def getInstanceCreator(self) -> ghidra.app.util.bin.format.golang.structmapping.StructureMappingInfo.ObjectInstanceCreator: ...

    def getMarkupFuncs(self) -> List[ghidra.app.util.bin.format.golang.structmapping.StructureMarkupFunction]: ...

    def getStructureDataType(self) -> ghidra.program.model.data.Structure: ...

    @staticmethod
    def getStructureDataTypeNameForClass(targetClass: java.lang.Class) -> unicode:
        """
        Returns the name of the structure data type that will define the binary layout 
         of the mapped fields in the target class.
        @param targetClass structure mapped class
        @return the structure name
        """
        ...

    def getStructureLength(self) -> int: ...

    def getStructureName(self) -> unicode: ...

    def getTargetClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def readStructure(self, context: ghidra.app.util.bin.format.golang.structmapping.StructureContext) -> None:
        """
        Deserializes a structure mapped instance by assigning values to its 
         {@link FieldMapping &#64;FieldMapping mapped} java fields.
        @param context {@link StructureContext}
        @throws IOException if error reading the structure
        """
        ...

    def recoverStructureContext(self, structureInstance: object) -> ghidra.app.util.bin.format.golang.structmapping.StructureContext:
        """
        Reaches into a structure mapped instance and extracts its StructureContext field value.
        @param structureInstance instance to query
        @return {@link StructureContext}, or null if error extracting value
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def afterMethods(self) -> List[object]: ...

    @property
    def description(self) -> unicode: ...

    @property
    def fields(self) -> List[object]: ...

    @property
    def instanceCreator(self) -> ghidra.app.util.bin.format.golang.structmapping.StructureMappingInfo.ObjectInstanceCreator: ...

    @property
    def markupFuncs(self) -> List[object]: ...

    @property
    def structureDataType(self) -> ghidra.program.model.data.Structure: ...

    @property
    def structureLength(self) -> int: ...

    @property
    def structureName(self) -> unicode: ...

    @property
    def targetClass(self) -> java.lang.Class: ...