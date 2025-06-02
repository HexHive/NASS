from typing import List
import ghidra.app.util.bin
import ghidra.app.util.bin.format.golang.structmapping
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.util
import ghidra.util.task
import java.lang


class DataTypeMapper(object, java.lang.AutoCloseable):
    """
    Information about StructureMapping classes and their metadata.
 
     To use the full might and majesty of StructureMapping(tm), a DataTypeMapper must be created. It
     must be able to #addArchiveSearchCategoryPath(CategoryPath...) 
     (#addProgramSearchCategoryPath(CategoryPath...)) the Ghidra structure data
     types being used, and it must #registerStructure(Class) about all classes that are
     going to participate during deserialization and markup.
 
     Structure mapped classes can receive a reference to the specific DataTypeMapper type that 
     created them by declaring a  field, and tagging it with 
     the @ContextField annotation:
 
 
     class MyDataTypeMapper extends DataTypeMapper {
      public MyDataTypeMapper() {
        ...
       registerStructure(MyDataType.class);
      }
      public void foo() { ... }
     }
 
     StructureMapping(structureName = "mydatatype")
     class MyDataType {
 
      ContextField
      private MyDataTypeMapper myDataTypeMapper;
  
      ContextField
      private StructureContextMyDataType context;
 
      FieldMapping
      private long someField;
 
     void bar() {
      context.getDataTypeMapper().getProgram(); // can only access methods defined on base DataTypeMapper type
      myDataTypeMapper.foo(); // same context as previous line, but typed correctly
     ...
 
    """









    def addArchiveSearchCategoryPath(self, paths: List[ghidra.program.model.data.CategoryPath]) -> None:
        """
        Adds category paths to a search list, used when looking for a data type.
         <p>
         See {@link #getType(String, Class)}.
        @param paths vararg list of {@link CategoryPath}s
        """
        ...

    def addProgramSearchCategoryPath(self, paths: List[ghidra.program.model.data.CategoryPath]) -> None:
        """
        Adds category paths to a search list, used when looking for a data type.
         <p>
         See {@link #getType(String, Class)}.
        @param paths vararg list of {@link CategoryPath}s
        """
        ...

    def close(self) -> None: ...

    def createMarkupSession(self, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.bin.format.golang.structmapping.MarkupSession:
        """
        Creates a {@link MarkupSession} that is controlled by the specified {@link TaskMonitor}.
        @param monitor {@link TaskMonitor}
        @return new {@link MarkupSession}
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getAddressOfStructure(self, structureInstance: object) -> ghidra.program.model.address.Address:
        """
        Attempts to convert an instance of an object (that represents a chunk of memory in
         the program) into its Address.
        @param <T> type of the object
        @param structureInstance instance of an object that represents something in the program's
         memory
        @return {@link Address} of the object, or null if not found or not a supported object
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getCodeAddress(self, offset: long) -> ghidra.program.model.address.Address:
        """
        Converts an offset into an Address.
        @param offset numeric offset
        @return {@link Address}
        """
        ...

    def getDTM(self) -> ghidra.program.model.data.DataTypeManager:
        """
        Returns the program's data type manager.
        @return program's {@link DataTypeManager}
        """
        ...

    def getDataAddress(self, offset: long) -> ghidra.program.model.address.Address:
        """
        Converts an offset into an Address.
        @param offset numeric offset
        @return {@link Address}
        """
        ...

    def getDataConverter(self) -> ghidra.util.DataConverter:
        """
        Returns a {@link DataConverter} appropriate for the current program.
        @return {@link DataConverter}
        """
        ...

    def getDefaultVariableLengthStructCategoryPath(self) -> ghidra.program.model.data.CategoryPath:
        """
        CategoryPath location (in the program) where new data types will be created to represent
         variable length structures.
        @return {@link CategoryPath}, default is ROOT
        """
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Returns the program.
        @return ghidra {@link Program}
        """
        ...

    def getReader(self, position: long) -> ghidra.app.util.bin.BinaryReader:
        """
        Creates a {@link BinaryReader}, at the specified position.
        @param position location in the program
        @return new {@link BinaryReader}
        """
        ...

    def getStructureContextOfInstance(self, structureInstance: object) -> ghidra.app.util.bin.format.golang.structmapping.StructureContext:
        """
        Returns the {@link StructureContext} of a structure mapped instance.
        @param <T> java type of a class that is structure mapped
        @param structureInstance an existing instance of type T
        @return {@link StructureContext} of the instance, or null if instance was null or not
         a structure mapped object
        """
        ...

    def getStructureDataType(self, clazz: java.lang.Class) -> ghidra.program.model.data.Structure:
        """
        Returns a Ghidra structure data type representing the specified class.
        @param clazz a structure mapped class
        @return {@link Structure} data type, or null if the class was a struct with variable length
         fields
        """
        ...

    def getStructureDataTypeName(self, clazz: java.lang.Class) -> unicode:
        """
        Returns the name of the Ghidra structure that has been registered for the specified
         structure mapped class.
        @param clazz a structure mapped class
        @return name of the corresponding Ghidra structure data type, or null if class was not
         registered
        """
        ...

    @overload
    def getStructureMappingInfo(self, clazz: java.lang.Class) -> ghidra.app.util.bin.format.golang.structmapping.StructureMappingInfo:
        """
        Returns the {@link StructureMappingInfo} for a class (that has already been registered).
        @param <T> structure mapped class type
        @param clazz the class
        @return {@link StructureMappingInfo} for the specified class, or null if the class was
         not previously {@link #registerStructure(Class) registered}
        """
        ...

    @overload
    def getStructureMappingInfo(self, structureInstance: object) -> ghidra.app.util.bin.format.golang.structmapping.StructureMappingInfo:
        """
        Returns the {@link StructureMappingInfo} for an object instance.
        @param <T> structure mapped class type
        @param structureInstance an instance of a previously registered 
         {@link StructureMapping structure mapping} class, or null
        @return {@link StructureMappingInfo} for the instance, or null if the class was
         not previously {@link #registerStructure(Class) registered}
        """
        ...

    def getType(self, name: unicode, clazz: java.lang.Class) -> object:
        """
        Returns a named {@link DataType}, searching the registered 
         {@link #addProgramSearchCategoryPath(CategoryPath...) program}
         and {@link #addArchiveSearchCategoryPath(CategoryPath...) archive} category paths.
         <p>
         DataTypes that were found in the attached archive gdt manager will be copied into the
         program's data type manager before being returned.
        @param <T> DataType or derived type
        @param name {@link DataType} name
        @param clazz expected DataType class
        @return DataType or null if not found
        """
        ...

    def getTypeOrDefault(self, __a0: unicode, __a1: java.lang.Class, __a2: ghidra.program.model.data.DataType) -> ghidra.program.model.data.DataType: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @overload
    def readStructure(self, structureClass: java.lang.Class, position: long) -> object:
        """
        Reads a structure mapped object from the specified position of the program.
        @param <T> type of object
        @param structureClass structure mapped object class
        @param position of object
        @return new object instance of type T
        @throws IOException if error reading
        @throws IllegalArgumentException if specified structureClass is not valid
        """
        ...

    @overload
    def readStructure(self, structureClass: java.lang.Class, structReader: ghidra.app.util.bin.BinaryReader) -> object:
        """
        Reads a structure mapped object from the current position of the specified BinaryReader.
        @param <T> type of object
        @param structureClass structure mapped object class
        @param structReader {@link BinaryReader} positioned at the start of an object
        @return new object instance of type T
        @throws IOException if error reading
        @throws IllegalArgumentException if specified structureClass is not valid
        """
        ...

    @overload
    def readStructure(self, structureClass: java.lang.Class, address: ghidra.program.model.address.Address) -> object:
        """
        Reads a structure mapped object from the specified Address of the program.
        @param <T> type of object
        @param structureClass structure mapped object class
        @param address location of object
        @return new object instance of type T
        @throws IOException if error reading
        @throws IllegalArgumentException if specified structureClass is not valid
        """
        ...

    def registerStructure(self, clazz: java.lang.Class) -> None:
        """
        Registers a class that has {@link StructureMapping structure mapping} information.
        @param <T> structure mapped class type
        @param clazz class that represents a structure, marked with {@link StructureMapping} 
         annotation
        @throws IOException if the class's Ghidra structure data type could not be found
        """
        ...

    def registerStructures(self, __a0: List[object]) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def DTM(self) -> ghidra.program.model.data.DataTypeManager: ...

    @property
    def dataConverter(self) -> ghidra.util.DataConverter: ...

    @property
    def defaultVariableLengthStructCategoryPath(self) -> ghidra.program.model.data.CategoryPath: ...

    @property
    def program(self) -> ghidra.program.model.listing.Program: ...