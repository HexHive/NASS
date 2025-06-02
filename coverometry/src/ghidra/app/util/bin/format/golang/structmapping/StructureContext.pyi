import ghidra.app.util.bin
import ghidra.app.util.bin.format.golang.structmapping
import ghidra.program.model.address
import ghidra.program.model.data
import java.lang


class StructureContext(object):
    """
    Information about an instance of a structure that has been read from the memory of a 
     Ghidra program.
 
     All StructureMapping tagged classes must have a ContextField tagged
     StructureContext field for that class to be able to access meta-data about its self, and
     for other classes to reference it when performing markup:
 
     StructureMapping(structureName = "mydatatype")
     class MyDataType {
     	ContextField
     	private StructureContextMyDataType context;
 
     	FieldMapping
     	private long someField;
      ...
 
    """





    def __init__(self, dataTypeMapper: ghidra.app.util.bin.format.golang.structmapping.DataTypeMapper, mappingInfo: ghidra.app.util.bin.format.golang.structmapping.StructureMappingInfo, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates an instance of a {@link StructureContext}.
        @param dataTypeMapper mapping context for the program
        @param mappingInfo mapping information about this structure
        @param reader {@link BinaryReader} positioned at the start of the structure to be read
        """
        ...



    def createFieldContext(self, fmi: ghidra.app.util.bin.format.golang.structmapping.FieldMappingInfo, includeReader: bool) -> ghidra.app.util.bin.format.golang.structmapping.FieldContext:
        """
        Creates a new {@link FieldContext} for a specific field.
        @param fmi {@link FieldMappingInfo field} of interest
        @param includeReader boolean flag, if true create a BinaryReader for the field, if false no
         BinaryReader will be created
        @return new {@link FieldContext}
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDataTypeMapper(self) -> ghidra.app.util.bin.format.golang.structmapping.DataTypeMapper:
        """
        Returns a reference to the root {@link DataTypeMapper}, as a plain DataTypeMapper type.  If
         a more specific DataTypeMapper type is needed, either type-cast this value, or use
         a {@link ContextField} tag on a field in your class that specifies the correct 
         DataTypeMapper type.
        @return the program mapping context that control's this structure instance
        """
        ...

    def getFieldAddress(self, fieldOffset: long) -> ghidra.program.model.address.Address:
        """
        Returns the address of an offset from the start of this structure instance.
        @param fieldOffset number of bytes from the beginning of this structure where a field (or
         other location of interest) starts
        @return {@link Address} of specified offset
        """
        ...

    def getFieldLocation(self, fieldOffset: long) -> long:
        """
        Returns the stream location of an offset from the start of this structure instance.
        @param fieldOffset number of bytes from the beginning of this structure where a field (or
         other location of interest) starts
        @return absolute offset / position in the program / BinaryReader stream
        """
        ...

    def getFieldReader(self, fieldOffset: long) -> ghidra.app.util.bin.BinaryReader:
        """
        Returns an independent {@link BinaryReader} that is positioned at the start of the
         specified field.
        @param fieldOffset number of bytes from the beginning of this structure where a field (or
         other location of interest) starts
        @return new {@link BinaryReader} positioned at the specified relative offset
        """
        ...

    def getMappingInfo(self) -> ghidra.app.util.bin.format.golang.structmapping.StructureMappingInfo:
        """
        Returns the {@link StructureMappingInfo} for this structure's class.
        @return {@link StructureMappingInfo} for this structure's class
        """
        ...

    def getReader(self) -> ghidra.app.util.bin.BinaryReader:
        """
        Returns the {@link BinaryReader} that is used to deserialize this structure.
        @return {@link BinaryReader} that is used to deserialize this structure
        """
        ...

    def getStructureAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the address in the program of this structure instance.
        @return {@link Address}
        """
        ...

    def getStructureDataType(self) -> ghidra.program.model.data.Structure:
        """
        Returns the Ghidra {@link Structure structure data type} that represents this object.
         <p>
         If this is an instance of a variable length structure mapped class, a custom structure data
         type will be minted that exactly matches this instance's variable length fields.
        @return Ghidra {@link Structure structure data type} that represents this object
        @throws IOException if error constructing new struct data type
        """
        ...

    def getStructureEnd(self) -> long:
        """
        Returns the stream location of the end of this structure instance.
        @return absolute offset / position in the program / BinaryReader stream of the byte after
         this structure
        """
        ...

    def getStructureInstance(self) -> object:
        """
        Returns a reference to the object instance that was deserialized.
        @return reference to deserialized structure mapped object
        """
        ...

    def getStructureLength(self) -> int:
        """
        Returns the length of this structure instance.
        @return length of this structure, or 0 if this structure is a variable length structure
         that does not have a fixed length
        """
        ...

    def getStructureStart(self) -> long:
        """
        Returns the stream location of this structure instance.
        @return absolute offset / position in the program / BinaryReader stream of this structure
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def readNewInstance(self) -> object:
        """
        Creates a new instance of the structure by deserializing the structure's marked
         fields into java fields.
        @return new instance of structure
        @throws IOException if error reading
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
    def dataTypeMapper(self) -> ghidra.app.util.bin.format.golang.structmapping.DataTypeMapper: ...

    @property
    def mappingInfo(self) -> ghidra.app.util.bin.format.golang.structmapping.StructureMappingInfo: ...

    @property
    def reader(self) -> ghidra.app.util.bin.BinaryReader: ...

    @property
    def structureAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def structureDataType(self) -> ghidra.program.model.data.Structure: ...

    @property
    def structureEnd(self) -> long: ...

    @property
    def structureInstance(self) -> object: ...

    @property
    def structureLength(self) -> int: ...

    @property
    def structureStart(self) -> long: ...