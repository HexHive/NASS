from typing import List
import generic.jar
import ghidra.app.util.bin
import ghidra.app.util.bin.format.golang
import ghidra.app.util.bin.format.golang.rtti
import ghidra.app.util.bin.format.golang.rtti.types
import ghidra.app.util.bin.format.golang.structmapping
import ghidra.app.util.importer
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.util
import ghidra.util.task
import java.io
import java.lang


class GoRttiMapper(ghidra.app.util.bin.format.golang.structmapping.DataTypeMapper):
    """
    DataTypeMapper for golang binaries. 
 
     When bootstrapping golang binaries, the following steps are used:
 
     	Find the GoBuildInfo struct.  This struct is the easiest to locate, even when the binary
     	is stripped.  This gives us the go pointerSize (probably same as ghidra pointer size) and the
     	goVersion.  This struct does not rely on StructureMapping, allowing its use before a
     	DataTypeMapper is created.
     	Create DataTypeMapper
     	Find the runtime.firstmoduledata structure.
 		
    			If there are symbols, just use the symbol or named memory block.
    			If stripped:
				
     					Find the pclntab.  This has a magic signature, a pointerSize, and references
     					to a couple of tables that are also referenced in the moduledata structure.
     					Search memory for a pointer to the pclntab struct.  This should be the first
     					field of the moduledata structure.  The values that are duplicated between the
     					two structures can be compared to ensure validity.
     					Different binary formats (Elf vs PE) will determine which memory blocks to
     					search.
 				  
 		
 
    """





    def __init__(self, program: ghidra.program.model.listing.Program, ptrSize: int, endian: ghidra.program.model.lang.Endian, goVersion: ghidra.app.util.bin.format.golang.GoVer, archiveGDT: generic.jar.ResourceFile):
        """
        Creates a GoRttiMapper using the specified bootstrap information.
        @param program {@link Program} containing the go binary
        @param ptrSize size of pointers
        @param endian {@link Endian}
        @param goVersion version of go
        @param archiveGDT path to the matching golang bootstrap gdt data type file, or null
         if not present and types recovered via DWARF should be used instead
        @throws IOException if error linking a structure mapped structure to its matching
         ghidra structure, which is a programming error or a corrupted bootstrap gdt
        @throws IllegalArgumentException if there is no matching bootstrap gdt for this specific
         type of golang binary
        """
        ...



    def addArchiveSearchCategoryPath(self, paths: List[ghidra.program.model.data.CategoryPath]) -> None:
        """
        Adds category paths to a search list, used when looking for a data type.
         <p>
         See {@link #getType(String, Class)}.
        @param paths vararg list of {@link CategoryPath}s
        """
        ...

    def addModule(self, module: ghidra.app.util.bin.format.golang.rtti.GoModuledata) -> None:
        """
        Adds a module data instance to the context
        @param module {@link GoModuledata} to add
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

    def cacheRecoveredDataType(self, typ: ghidra.app.util.bin.format.golang.rtti.types.GoType, dt: ghidra.program.model.data.DataType) -> None:
        """
        Inserts a mapping between a {@link GoType golang type} and a 
         {@link DataType ghidra data type}.
         <p>
         Useful to prepopulate the data type mapping before recursing into contained/referenced types
         that might be self-referencing.
        @param typ {@link GoType golang type}
        @param dt {@link DataType Ghidra type}
        @throws IOException if golang type struct is not a valid struct mapped instance
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

    def discoverGoTypes(self, monitor: ghidra.util.task.TaskMonitor) -> None:
        """
        Iterates over all golang rtti types listed in the GoModuledata struct, and recurses into
         each type to discover any types they reference.
         <p>
         The found types are accumulated in {@link #goTypes}.
        @param monitor {@link TaskMonitor}
        @throws IOException if error
        @throws CancelledException if cancelled
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def exportTypesToGDT(self, gdtFile: java.io.File, monitor: ghidra.util.task.TaskMonitor) -> None:
        """
        Export the currently registered struct mapping types to a gdt file, producing a bootstrap
         GDT archive.
         <p>
         The struct data types will either be from the current program's DWARF data, or
         from an earlier golang.gdt (if this binary doesn't have DWARF)
        @param gdtFile destination {@link File} to write the bootstrap types to
        @param monitor {@link TaskMonitor}
        @throws IOException if error
        """
        ...

    def findContainingModule(self, offset: long) -> ghidra.app.util.bin.format.golang.rtti.GoModuledata:
        """
        Finds the {@link GoModuledata} that contains the specified offset.
         <p>
         Useful for finding the {@link GoModuledata} to resolve a relative offset of the text,
         types or other area.
        @param offset absolute offset of a structure that a {@link GoModuledata} contains
        @return {@link GoModuledata} instance that contains the structure, or null if not found
        """
        ...

    def findContainingModuleByFuncData(self, offset: long) -> ghidra.app.util.bin.format.golang.rtti.GoModuledata:
        """
        Finds the {@link GoModuledata} that contains the specified func data offset.
        @param offset absolute offset of a func data structure
        @return {@link GoModuledata} instance that contains the specified func data, or null if not
         found
        """
        ...

    def findGoType(self, typeName: unicode) -> ghidra.app.util.bin.format.golang.rtti.types.GoType:
        """
        Finds a go type by its go-type name, from the list of 
         {@link #discoverGoTypes(TaskMonitor) discovered} go types.
        @param typeName name string
        @return {@link GoType}, or null if not found
        """
        ...

    @staticmethod
    def findGolangBootstrapGDT(goVer: ghidra.app.util.bin.format.golang.GoVer, ptrSize: int, osName: unicode) -> generic.jar.ResourceFile:
        """
        Searches for a golang bootstrap gdt file that matches the specified Go version/size/OS.
         <p>
         First looks for a gdt with an exact match, then for a gdt with version/size match and
         "any" OS, and finally, a gdt that matches the version and "any" size and "any" OS.
        @param goVer version of Go
        @param ptrSize size of pointers
        @param osName name of OS
        @return ResourceFile of matching bootstrap gdt, or null if nothing matches
        """
        ...

    def getAbi0CallingConvention(self) -> ghidra.program.model.lang.PrototypeModel: ...

    def getAbiInternalCallingConvention(self) -> ghidra.program.model.lang.PrototypeModel: ...

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

    def getAllFunctions(self) -> List[ghidra.app.util.bin.format.golang.rtti.GoFuncData]: ...

    def getCachedRecoveredDataType(self, typ: ghidra.app.util.bin.format.golang.rtti.types.GoType) -> ghidra.program.model.data.DataType:
        """
        Returns a {@link DataType Ghidra data type} that represents the {@link GoType golang type}, 
         using a cache of already recovered types to eliminate extra work and self recursion.
        @param typ the {@link GoType} to convert
        @return Ghidra {@link DataType}
        @throws IOException if golang type struct is not a valid struct mapped instance
        """
        ...

    def getChanGoType(self) -> ghidra.app.util.bin.format.golang.rtti.types.GoType:
        """
        Returns the ghidra data type that represents the built-in golang channel type.
        @return golang channel type
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

    def getDefaultVariableLengthStructCategoryPath(self) -> ghidra.program.model.data.CategoryPath: ...

    def getDuffcopyCallingConvention(self) -> ghidra.program.model.lang.PrototypeModel: ...

    def getDuffzeroCallingConvention(self) -> ghidra.program.model.lang.PrototypeModel: ...

    def getFirstModule(self) -> ghidra.app.util.bin.format.golang.rtti.GoModuledata:
        """
        Returns the first module data instance
        @return {@link GoModuledata}
        """
        ...

    def getFunctionByName(self, funcName: unicode) -> ghidra.app.util.bin.format.golang.rtti.GoFuncData: ...

    def getFunctionData(self, funcAddr: ghidra.program.model.address.Address) -> ghidra.app.util.bin.format.golang.rtti.GoFuncData: ...

    @staticmethod
    def getGDTFilename(goVer: ghidra.app.util.bin.format.golang.GoVer, pointerSizeInBytes: int, osName: unicode) -> unicode:
        """
        Returns the name of the golang bootstrap gdt data type archive, using the specified
         version, pointer size and OS name.
        @param goVer {@link GoVer}
        @param pointerSizeInBytes pointer size for this binary, or -1 to use wildcard "any"
        @param osName name of the operating system, or "any"
        @return String, "golang_1.18_64bit_any.gdt"
        """
        ...

    def getGenericSliceDT(self) -> ghidra.program.model.data.Structure:
        """
        Returns the data type that represents a generic golang slice.
        @return golang generic slice data type
        """
        ...

    def getGhidraDataType(self, goTypeName: unicode, clazz: java.lang.Class) -> object:
        """
        Returns the Ghidra {@link DataType} that is equivalent to the named golang type.
        @param <T> expected DataType
        @param goTypeName golang type name
        @param clazz class of expected data type
        @return {@link DataType} representing the named golang type, or null if not found
        """
        ...

    def getGoName(self, offset: long) -> ghidra.app.util.bin.format.golang.rtti.GoName:
        """
        Returns the {@link GoName} instance at the specified offset.
        @param offset location to read
        @return {@link GoName} instance, or null if offset was special value 0
        @throws IOException if error reading
        """
        ...

    @overload
    def getGoType(self, offset: long) -> ghidra.app.util.bin.format.golang.rtti.types.GoType:
        """
        Returns a specialized {@link GoType} for the type that is located at the specified location.
        @param offset absolute position of a go type
        @return specialized {@link GoType} (example, GoStructType, GoArrayType, etc)
        @throws IOException if error reading
        """
        ...

    @overload
    def getGoType(self, addr: ghidra.program.model.address.Address) -> ghidra.app.util.bin.format.golang.rtti.types.GoType:
        """
        Returns a specialized {@link GoType} for the type that is located at the specified location.
        @param addr location of a go type
        @return specialized {@link GoType} (example, GoStructType, GoArrayType, etc)
        @throws IOException if error reading
        """
        ...

    @staticmethod
    def getGolangOSString(program: ghidra.program.model.listing.Program) -> unicode:
        """
        Returns a golang OS string based on the Ghidra program.
        @param program {@link Program}
        @return String golang OS string such as "linux", "win"
        """
        ...

    def getGolangVersion(self) -> ghidra.app.util.bin.format.golang.GoVer:
        """
        Returns the golang version
        @return {@link GoVer}
        """
        ...

    def getInt32DT(self) -> ghidra.program.model.data.DataType:
        """
        Returns the data type that represents a golang int32
        @return golang int32 data type
        """
        ...

    def getLastGoType(self) -> ghidra.app.util.bin.format.golang.rtti.types.GoType: ...

    def getMapGoType(self) -> ghidra.app.util.bin.format.golang.rtti.types.GoType:
        """
        Returns the ghidra data type that represents a golang built-in map type.
        @return golang map data type
        """
        ...

    @staticmethod
    def getMapperFor(program: ghidra.program.model.listing.Program, log: ghidra.app.util.importer.MessageLog) -> ghidra.app.util.bin.format.golang.rtti.GoRttiMapper:
        """
        Returns a new {@link GoRttiMapper} for the specified program, or null if the binary
         is not a supported golang binary.
        @param program {@link Program}
        @param log {@link MessageLog}
        @return new {@link GoRttiMapper}, or null if not a golang binary
        @throws IOException if bootstrap gdt is corrupted or some other struct mapping logic error
        """
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Returns the program.
        @return ghidra {@link Program}
        """
        ...

    def getPtrSize(self) -> int:
        """
        Returns the size of pointers in this binary.
        @return pointer size (ex. 4, or 8)
        """
        ...

    def getReader(self, position: long) -> ghidra.app.util.bin.BinaryReader:
        """
        Creates a {@link BinaryReader}, at the specified position.
        @param position location in the program
        @return new {@link BinaryReader}
        """
        ...

    def getRecoveredType(self, typ: ghidra.app.util.bin.format.golang.rtti.types.GoType) -> ghidra.program.model.data.DataType:
        """
        Returns a {@link DataType Ghidra data type} that represents the {@link GoType golang type}, 
         using a cache of already recovered types to eliminate extra work and self recursion.
        @param typ the {@link GoType} to convert
        @return Ghidra {@link DataType}
        @throws IOException if error converting type
        """
        ...

    def getRecoveredTypesCp(self) -> ghidra.program.model.data.CategoryPath:
        """
        Returns category path that should be used to place recovered golang types.
        @return {@link CategoryPath} to use when creating recovered golang types
        """
        ...

    def getRegInfo(self) -> ghidra.app.util.bin.format.golang.GoRegisterInfo: ...

    def getStorageAllocator(self) -> ghidra.app.util.bin.format.golang.GoParamStorageAllocator: ...

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

    def getUint32DT(self) -> ghidra.program.model.data.DataType:
        """
        Returns the data type that represents a golang uint32
        @return golang uint32 data type
        """
        ...

    def getUintptrDT(self) -> ghidra.program.model.data.DataType:
        """
        Returns the data type that represents a golang uintptr
        @return golang uinptr data type
        """
        ...

    def hashCode(self) -> int: ...

    def init(self, monitor: ghidra.util.task.TaskMonitor) -> None: ...

    def isGolangAbi0Func(self, func: ghidra.program.model.listing.Function) -> bool: ...

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

    def recoverDataTypes(self, monitor: ghidra.util.task.TaskMonitor) -> None:
        """
        Converts all discovered golang rtti type records to Ghidra data types, placing them
         in the program's DTM in /golang-recovered
        @param monitor {@link TaskMonitor}
        @throws IOException error converting a golang type to a Ghidra type
        @throws CancelledException if the user cancelled the import
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

    def resolveNameOff(self, ptrInModule: long, off: long) -> ghidra.app.util.bin.format.golang.rtti.GoName:
        """
        Returns the {@link GoName} corresponding to an offset that is relative to the controlling
         GoModuledata's typesOffset.
         <p>
        @param ptrInModule the address of the structure that contains the offset that needs to be
         calculated.  The containing-structure's address is important because it indicates which
         GoModuledata is the 'parent'
        @param off offset
        @return {@link GoName}, or null if offset was special value 0
        @throws IOException if error reading name or unable to find containing module
        """
        ...

    def resolveTextOff(self, ptrInModule: long, off: long) -> ghidra.program.model.address.Address:
        """
        Returns the {@link Address} to an offset that is relative to the controlling
         GoModuledata's text value.
        @param ptrInModule the address of the structure that contains the offset that needs to be
         calculated.  The containing-structure's address is important because it indicates which
         GoModuledata is the 'parent'
        @param off offset
        @return {@link Address}, or null if offset was special value -1
        """
        ...

    def resolveTypeOff(self, ptrInModule: long, off: long) -> ghidra.app.util.bin.format.golang.rtti.types.GoType:
        """
        Returns the {@link GoType} corresponding to an offset that is relative to the controlling
         GoModuledata's typesOffset.
        @param ptrInModule the address of the structure that contains the offset that needs to be
         calculated.  The containing-structure's address is important because it indicates which
         GoModuledata is the 'parent'
        @param off offset
        @return {@link GoType}, or null if offset is special value 0 or -1
        @throws IOException if error
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
    def abi0CallingConvention(self) -> ghidra.program.model.lang.PrototypeModel: ...

    @property
    def abiInternalCallingConvention(self) -> ghidra.program.model.lang.PrototypeModel: ...

    @property
    def allFunctions(self) -> List[object]: ...

    @property
    def chanGoType(self) -> ghidra.app.util.bin.format.golang.rtti.types.GoType: ...

    @property
    def defaultVariableLengthStructCategoryPath(self) -> ghidra.program.model.data.CategoryPath: ...

    @property
    def duffcopyCallingConvention(self) -> ghidra.program.model.lang.PrototypeModel: ...

    @property
    def duffzeroCallingConvention(self) -> ghidra.program.model.lang.PrototypeModel: ...

    @property
    def firstModule(self) -> ghidra.app.util.bin.format.golang.rtti.GoModuledata: ...

    @property
    def genericSliceDT(self) -> ghidra.program.model.data.Structure: ...

    @property
    def golangVersion(self) -> ghidra.app.util.bin.format.golang.GoVer: ...

    @property
    def int32DT(self) -> ghidra.program.model.data.DataType: ...

    @property
    def lastGoType(self) -> ghidra.app.util.bin.format.golang.rtti.types.GoType: ...

    @property
    def mapGoType(self) -> ghidra.app.util.bin.format.golang.rtti.types.GoType: ...

    @property
    def ptrSize(self) -> int: ...

    @property
    def recoveredTypesCp(self) -> ghidra.program.model.data.CategoryPath: ...

    @property
    def regInfo(self) -> ghidra.app.util.bin.format.golang.GoRegisterInfo: ...

    @property
    def storageAllocator(self) -> ghidra.app.util.bin.format.golang.GoParamStorageAllocator: ...

    @property
    def uint32DT(self) -> ghidra.program.model.data.DataType: ...

    @property
    def uintptrDT(self) -> ghidra.program.model.data.DataType: ...