from typing import List
import ghidra.app.util.bin
import ghidra.app.util.bin.format.pe
import ghidra.app.util.bin.format.pe.cli
import ghidra.app.util.importer
import ghidra.docking.settings
import ghidra.program.database.data
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.util
import ghidra.util.task
import java.lang
import java.net
import java.util


class ImageCor20Header(object, ghidra.app.util.bin.StructConverter, ghidra.app.util.bin.format.pe.PeMarkupable):
    """
    typedef struct IMAGE_COR20_HEADER
     {
         // Header versioning
        DWORD                   cb;                      // Size of the structure
        WORD                    MajorRuntimeVersion;     // Version of the CLR Runtime
        WORD                    MinorRuntimeVersion;     // Version of the CLR Runtime

        // Symbol table and startup information
        IMAGE_DATA_DIRECTORY    MetaData;                // A Data Directory giving RVA and Size of MetaData
        DWORD                   Flags;
        union {
          DWORD                 EntryPointRVA;           // Points to the .NET native EntryPoint method
          DWORD                 EntryPointToken;         // Points to the .NET IL EntryPoint method
        };

        // Binding information
        IMAGE_DATA_DIRECTORY    Resources;               // A Data Directory for Resources, which are referenced in the MetaData
        IMAGE_DATA_DIRECTORY    StrongNameSignature;     // A Data Directory for unique .NET assembly signatures

        // Regular fixup and binding information
        IMAGE_DATA_DIRECTORY    CodeManagerTable;        // Always 0
        IMAGE_DATA_DIRECTORY    VTableFixups;            // Not well documented VTable used by languages who don't follow the common type system runtime model
        IMAGE_DATA_DIRECTORY    ExportAddressTableJumps; // Always 0 in normal .NET assemblies, only present in native images

        // Precompiled image info (internal use only - set to zero)
        IMAGE_DATA_DIRECTORY    ManagedNativeHeader;

    };

    """

    ASCII: ghidra.program.model.data.DataType = char
    BYTE: ghidra.program.model.data.DataType = byte
    DWORD: ghidra.program.model.data.DataType = dword
    IBO32: ghidra.program.model.data.DataType = IBO32DataType: typedef ImageBaseOffset32 pointer32
    IBO64: ghidra.program.model.data.DataType = IBO64DataType: typedef ImageBaseOffset64 pointer64
    POINTER: ghidra.program.model.data.DataType = pointer
    QWORD: ghidra.program.model.data.DataType = qword
    SLEB128: ghidra.program.model.data.SignedLeb128DataType = sleb128
    STRING: ghidra.program.model.data.DataType = string
    ULEB128: ghidra.program.model.data.UnsignedLeb128DataType = uleb128
    UTF16: ghidra.program.model.data.DataType = unicode
    UTF8: ghidra.program.model.data.DataType = string-utf8
    VOID: ghidra.program.model.data.DataType = void
    WORD: ghidra.program.model.data.DataType = word




    class ImageCor20Flags(ghidra.program.model.data.EnumDataType):
        COMIMAGE_FLAGS_32BITREQUIRED: int = 2
        COMIMAGE_FLAGS_ILONLY: int = 1
        COMIMAGE_FLAGS_IL_LIBRARY: int = 4
        COMIMAGE_FLAGS_NATIVE_ENTRYPOINT: int = 16
        COMIMAGE_FLAGS_STRONGNAMESIGNED: int = 8
        COMIMAGE_FLAGS_TRACKDEBUGDATA: int = 65536
        PATH: unicode = u'/PE/CLI/Flags'



        def __init__(self): ...



        @overload
        def add(self, __a0: unicode, __a1: long) -> None: ...

        @overload
        def add(self, __a0: unicode, __a1: long, __a2: unicode) -> None: ...

        def addParent(self, __a0: ghidra.program.model.data.DataType) -> None: ...

        def clone(self, __a0: ghidra.program.model.data.DataTypeManager) -> ghidra.program.model.data.DataType: ...

        @overload
        def contains(self, __a0: long) -> bool: ...

        @overload
        def contains(self, __a0: unicode) -> bool: ...

        def copy(self, __a0: ghidra.program.model.data.DataTypeManager) -> ghidra.program.model.data.DataType: ...

        def dataTypeAlignmentChanged(self, __a0: ghidra.program.model.data.DataType) -> None: ...

        def dataTypeDeleted(self, __a0: ghidra.program.model.data.DataType) -> None: ...

        def dataTypeNameChanged(self, __a0: ghidra.program.model.data.DataType, __a1: unicode) -> None: ...

        def dataTypeReplaced(self, __a0: ghidra.program.model.data.DataType, __a1: ghidra.program.model.data.DataType) -> None: ...

        def dataTypeSizeChanged(self, __a0: ghidra.program.model.data.DataType) -> None: ...

        def dependsOn(self, __a0: ghidra.program.model.data.DataType) -> bool: ...

        def encodeRepresentation(self, __a0: unicode, __a1: ghidra.program.model.mem.MemBuffer, __a2: ghidra.docking.settings.Settings, __a3: int) -> List[int]: ...

        def encodeValue(self, __a0: object, __a1: ghidra.program.model.mem.MemBuffer, __a2: ghidra.docking.settings.Settings, __a3: int) -> List[int]: ...

        def equals(self, __a0: object) -> bool: ...

        def getAlignedLength(self) -> int: ...

        def getAlignment(self) -> int: ...

        def getCategoryPath(self) -> ghidra.program.model.data.CategoryPath: ...

        def getClass(self) -> java.lang.Class: ...

        def getComment(self, __a0: unicode) -> unicode: ...

        def getCount(self) -> int: ...

        def getDataOrganization(self) -> ghidra.program.model.data.DataOrganization: ...

        def getDataTypeManager(self) -> ghidra.program.model.data.DataTypeManager: ...

        def getDataTypePath(self) -> ghidra.program.model.data.DataTypePath: ...

        def getDefaultAbbreviatedLabelPrefix(self) -> unicode: ...

        @overload
        def getDefaultLabelPrefix(self) -> unicode: ...

        @overload
        def getDefaultLabelPrefix(self, __a0: ghidra.program.model.mem.MemBuffer, __a1: ghidra.docking.settings.Settings, __a2: int, __a3: ghidra.program.model.data.DataTypeDisplayOptions) -> unicode: ...

        def getDefaultOffcutLabelPrefix(self, __a0: ghidra.program.model.mem.MemBuffer, __a1: ghidra.docking.settings.Settings, __a2: int, __a3: ghidra.program.model.data.DataTypeDisplayOptions, __a4: int) -> unicode: ...

        def getDefaultSettings(self) -> ghidra.docking.settings.Settings: ...

        def getDescription(self) -> unicode: ...

        def getDisplayName(self) -> unicode: ...

        def getDocs(self) -> java.net.URL: ...

        def getLastChangeTime(self) -> long: ...

        def getLastChangeTimeInSourceArchive(self) -> long: ...

        def getLength(self) -> int: ...

        def getMaxPossibleValue(self) -> long: ...

        def getMinPossibleValue(self) -> long: ...

        def getMinimumPossibleLength(self) -> int: ...

        def getMnemonic(self, __a0: ghidra.docking.settings.Settings) -> unicode: ...

        @overload
        def getName(self) -> unicode: ...

        @overload
        def getName(self, __a0: long) -> unicode: ...

        @overload
        def getNames(self) -> List[unicode]: ...

        @overload
        def getNames(self, __a0: long) -> List[unicode]: ...

        def getParents(self) -> java.util.Collection: ...

        def getPathName(self) -> unicode: ...

        @overload
        def getRepresentation(self, __a0: ghidra.program.model.mem.MemBuffer, __a1: ghidra.docking.settings.Settings, __a2: int) -> unicode: ...

        @overload
        def getRepresentation(self, __a0: long, __a1: ghidra.docking.settings.Settings, __a2: int) -> unicode: ...

        def getSettingsDefinitions(self) -> List[ghidra.docking.settings.SettingsDefinition]: ...

        def getSignedState(self) -> ghidra.program.database.data.EnumSignedState: ...

        def getSourceArchive(self) -> ghidra.program.model.data.SourceArchive: ...

        def getTypeDefSettingsDefinitions(self) -> List[ghidra.program.model.data.TypeDefSettingsDefinition]: ...

        def getUniversalID(self) -> ghidra.util.UniversalID: ...

        @overload
        def getValue(self, __a0: unicode) -> long: ...

        @overload
        def getValue(self, __a0: ghidra.program.model.mem.MemBuffer, __a1: ghidra.docking.settings.Settings, __a2: int) -> object: ...

        def getValueClass(self, __a0: ghidra.docking.settings.Settings) -> java.lang.Class: ...

        def getValues(self) -> List[long]: ...

        def hasLanguageDependantLength(self) -> bool: ...

        def hashCode(self) -> int: ...

        def isDeleted(self) -> bool: ...

        def isEncodable(self) -> bool: ...

        def isEquivalent(self, __a0: ghidra.program.model.data.DataType) -> bool: ...

        def isNotYetDefined(self) -> bool: ...

        def isSigned(self) -> bool: ...

        def isZeroLength(self) -> bool: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def pack(self) -> None: ...

        def remove(self, __a0: unicode) -> None: ...

        def removeParent(self, __a0: ghidra.program.model.data.DataType) -> None: ...

        def replaceWith(self, __a0: ghidra.program.model.data.DataType) -> None: ...

        def setCategoryPath(self, __a0: ghidra.program.model.data.CategoryPath) -> None: ...

        def setDescription(self, __a0: unicode) -> None: ...

        def setLastChangeTime(self, __a0: long) -> None: ...

        def setLastChangeTimeInSourceArchive(self, __a0: long) -> None: ...

        def setLength(self, __a0: int) -> None: ...

        def setName(self, __a0: unicode) -> None: ...

        def setNameAndCategory(self, __a0: ghidra.program.model.data.CategoryPath, __a1: unicode) -> None: ...

        def setSourceArchive(self, __a0: ghidra.program.model.data.SourceArchive) -> None: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...







    def equals(self, __a0: object) -> bool: ...

    def getCb(self) -> int:
        """
        Gets the size of this structure in bytes.
        @return The size of this structure in bytes.
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getCodeManagerTable(self) -> ghidra.app.util.bin.format.pe.DefaultDataDirectory:
        """
        Gets the CodeManagerTable directory.
        @return The CodeManagerTable directory.
        """
        ...

    def getEntryPointToken(self) -> int:
        """
        Gets the entry point token.
        @return The entry point token.
        """
        ...

    def getEntryPointVA(self) -> ghidra.program.model.address.Address:
        """
        Gets the entry point virtual address.
        @return The entry point address.
        """
        ...

    def getExportAddressTableJumps(self) -> ghidra.app.util.bin.format.pe.DefaultDataDirectory:
        """
        Gets the ExportAddressTableJumps directory.
        @return The ExportAddressTableJumps directory.
        """
        ...

    def getFlags(self) -> int:
        """
        Gets the flags.
        @return The flags.
        """
        ...

    def getMajorRuntimeVersion(self) -> int:
        """
        Gets the major runtime version.
        @return The major runtime version.
        """
        ...

    def getManagedNativeHeader(self) -> ghidra.app.util.bin.format.pe.DefaultDataDirectory:
        """
        Gets the ManagedNativeHeader directory.
        @return The ManagedNativeHeader directory.
        """
        ...

    def getMetadata(self) -> ghidra.app.util.bin.format.pe.cli.CliMetadataDirectory:
        """
        Gets the MetaData directory.
        @return The MetaData directory.
        """
        ...

    def getMinorRuntimeVersion(self) -> int:
        """
        Gets the major runtime version.
        @return The major runtime version.
        """
        ...

    def getResources(self) -> ghidra.app.util.bin.format.pe.DefaultDataDirectory:
        """
        Gets the Resources directory.
        @return The Resources directory.
        """
        ...

    def getStrongNameSignature(self) -> ghidra.app.util.bin.format.pe.DefaultDataDirectory:
        """
        Gets the StrongNameSignature directory.
        @return The StrongNameSignature directory.
        """
        ...

    def getVTableFixups(self) -> ghidra.app.util.bin.format.pe.DefaultDataDirectory:
        """
        Gets the VTableFixups directory.
        @return The VTableFixups directory.
        """
        ...

    def hashCode(self) -> int: ...

    def markup(self, program: ghidra.program.model.listing.Program, isBinary: bool, monitor: ghidra.util.task.TaskMonitor, log: ghidra.app.util.importer.MessageLog, ntHeader: ghidra.app.util.bin.format.pe.NTHeader) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def parse(self) -> bool:
        """
        Parses this header
        @return True if parsing completed successfully; otherwise, false.
        @throws IOException If there was an IO problem while parsing.
        """
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def VTableFixups(self) -> ghidra.app.util.bin.format.pe.DefaultDataDirectory: ...

    @property
    def cb(self) -> int: ...

    @property
    def codeManagerTable(self) -> ghidra.app.util.bin.format.pe.DefaultDataDirectory: ...

    @property
    def entryPointToken(self) -> int: ...

    @property
    def entryPointVA(self) -> ghidra.program.model.address.Address: ...

    @property
    def exportAddressTableJumps(self) -> ghidra.app.util.bin.format.pe.DefaultDataDirectory: ...

    @property
    def flags(self) -> int: ...

    @property
    def majorRuntimeVersion(self) -> int: ...

    @property
    def managedNativeHeader(self) -> ghidra.app.util.bin.format.pe.DefaultDataDirectory: ...

    @property
    def metadata(self) -> ghidra.app.util.bin.format.pe.cli.CliMetadataDirectory: ...

    @property
    def minorRuntimeVersion(self) -> int: ...

    @property
    def resources(self) -> ghidra.app.util.bin.format.pe.DefaultDataDirectory: ...

    @property
    def strongNameSignature(self) -> ghidra.app.util.bin.format.pe.DefaultDataDirectory: ...