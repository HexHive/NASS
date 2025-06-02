from typing import List
import ghidra.docking.settings
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.mem
import ghidra.util
import java.lang
import java.net
import java.util


class WEVTResourceDataType(ghidra.program.model.data.DynamicDataType):




    @overload
    def __init__(self): ...

    @overload
    def __init__(self, dtm: ghidra.program.model.data.DataTypeManager): ...



    def addParent(self, dt: ghidra.program.model.data.DataType) -> None: ...

    def canSpecifyLength(self) -> bool: ...

    def clone(self, dtm: ghidra.program.model.data.DataTypeManager) -> ghidra.program.model.data.DataType: ...

    def copy(self, dtm: ghidra.program.model.data.DataTypeManager) -> ghidra.program.model.data.DataType:
        """
        Returns a clone of this built-in DataType
        @see ghidra.program.model.data.DataType#copy(ghidra.program.model.data.DataTypeManager)
        """
        ...

    def dataTypeAlignmentChanged(self, dt: ghidra.program.model.data.DataType) -> None: ...

    def dataTypeDeleted(self, dt: ghidra.program.model.data.DataType) -> None: ...

    def dataTypeNameChanged(self, dt: ghidra.program.model.data.DataType, oldName: unicode) -> None: ...

    def dataTypeReplaced(self, oldDt: ghidra.program.model.data.DataType, newDt: ghidra.program.model.data.DataType) -> None: ...

    def dataTypeSizeChanged(self, dt: ghidra.program.model.data.DataType) -> None: ...

    def dependsOn(self, dt: ghidra.program.model.data.DataType) -> bool: ...

    def encodeRepresentation(self, repr: unicode, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: int) -> List[int]: ...

    def encodeValue(self, value: object, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: int) -> List[int]: ...

    def equals(self, obj: object) -> bool: ...

    def getAlignedLength(self) -> int: ...

    def getAlignment(self) -> int: ...

    def getCTypeDeclaration(self, dataOrganization: ghidra.program.model.data.DataOrganization) -> unicode:
        """
        Returns null for FactoryDataType (which should never be used) and Dynamic types which should
         generally be replaced by a primitive array (e.g., char[5]) or, a primitive pointer (e.g., char *).
         For other types an appropriately sized unsigned integer typedef is returned.
        @see ghidra.program.model.data.BuiltInDataType#getCTypeDeclaration(ghidra.program.model.data.DataOrganization)
        """
        ...

    def getCategoryPath(self) -> ghidra.program.model.data.CategoryPath: ...

    def getClass(self) -> java.lang.Class: ...

    def getComponent(self, ordinal: int, buf: ghidra.program.model.mem.MemBuffer) -> ghidra.program.model.data.DataTypeComponent:
        """
        Returns the immediate n'th component of this data type.
        @param ordinal the components ordinal (zero based).
        @param buf a memory buffer to be used by dataTypes that change depending on
         their data context.
        @return the component data type or null if there is no component at the 
         indicated index.
        @throws ArrayIndexOutOfBoundsException if index is out of bounds
        """
        ...

    def getComponentAt(self, offset: int, buf: ghidra.program.model.mem.MemBuffer) -> ghidra.program.model.data.DataTypeComponent:
        """
        Returns the first component containing the byte at the given offset.
         It is possible with zero-length components (see {@link DataType#isZeroLength()})
         and bitfields (see @DataTypeComponent#isBitFieldComponent()} for multiple components
         to share the same offset.
        @param offset the offset into the dataType
        @param buf the memory buffer containing the bytes.
        @return the first component containing the byte at the given offset or null if no
         component defined.  A zero-length component may be returned.
        """
        ...

    def getComponents(self, buf: ghidra.program.model.mem.MemBuffer) -> List[ghidra.program.model.data.DataTypeComponent]:
        """
        Returns an array of components that make up this data type.
         Could return null if there are no subcomponents.
        @param buf a memory buffer to be used by dataTypes that change depending on
         their data context.
        @return datatype component array or null.
        """
        ...

    def getDataOrganization(self) -> ghidra.program.model.data.DataOrganization: ...

    def getDataTypeManager(self) -> ghidra.program.model.data.DataTypeManager:
        """
        @see ghidra.program.model.data.DataType#getDataTypeManager()
        """
        ...

    def getDataTypePath(self) -> ghidra.program.model.data.DataTypePath: ...

    def getDecompilerDisplayName(self, language: ghidra.program.model.lang.DecompilerLanguage) -> unicode:
        """
        Return token used to represent this type in decompiler/source-code output
        @param language is the language being displayed
        @return the name string
        """
        ...

    def getDefaultAbbreviatedLabelPrefix(self) -> unicode: ...

    @overload
    def getDefaultLabelPrefix(self) -> unicode: ...

    @overload
    def getDefaultLabelPrefix(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, len: int, options: ghidra.program.model.data.DataTypeDisplayOptions) -> unicode: ...

    def getDefaultOffcutLabelPrefix(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, len: int, options: ghidra.program.model.data.DataTypeDisplayOptions, offcutLength: int) -> unicode: ...

    def getDefaultSettings(self) -> ghidra.docking.settings.Settings: ...

    def getDescription(self) -> unicode: ...

    def getDisplayName(self) -> unicode: ...

    def getDocs(self) -> java.net.URL: ...

    def getLastChangeTime(self) -> long: ...

    def getLastChangeTimeInSourceArchive(self) -> long: ...

    @overload
    def getLength(self) -> int: ...

    @overload
    def getLength(self, buf: ghidra.program.model.mem.MemBuffer, maxLength: int) -> int: ...

    def getMnemonic(self, settings: ghidra.docking.settings.Settings) -> unicode: ...

    def getName(self) -> unicode: ...

    def getNumComponents(self, buf: ghidra.program.model.mem.MemBuffer) -> int:
        """
        Gets the number of component data types in this data type.
        @param buf a memory buffer to be used by dataTypes that change depending on
         their data context.
        @return the number of components that make up this data prototype
           - if this is an Array, return the number of elements in the array.
           - if this datatype is a subcomponent of another datatype and it
              won't fit in it's defined space, return -1.
        """
        ...

    def getParents(self) -> java.util.Collection: ...

    def getPathName(self) -> unicode: ...

    def getReplacementBaseType(self) -> ghidra.program.model.data.DataType: ...

    def getRepresentation(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: int) -> unicode:
        """
        @see ghidra.program.model.data.DataType#getRepresentation(ghidra.program.model.mem.MemBuffer, ghidra.docking.settings.Settings, int)
        """
        ...

    def getSettingsDefinitions(self) -> List[ghidra.docking.settings.SettingsDefinition]:
        """
        Gets a list of all the settingsDefinitions used by this datatype.
        @return a list of the settingsDefinitions used by this datatype.
        """
        ...

    def getSourceArchive(self) -> ghidra.program.model.data.SourceArchive: ...

    def getTypeDefSettingsDefinitions(self) -> List[ghidra.program.model.data.TypeDefSettingsDefinition]: ...

    def getUniversalID(self) -> ghidra.util.UniversalID: ...

    def getValue(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: int) -> object: ...

    def getValueClass(self, settings: ghidra.docking.settings.Settings) -> java.lang.Class: ...

    def hasLanguageDependantLength(self) -> bool: ...

    def hashCode(self) -> int: ...

    def invalidateCache(self) -> None: ...

    def isDeleted(self) -> bool: ...

    def isEncodable(self) -> bool: ...

    def isEquivalent(self, dt: ghidra.program.model.data.DataType) -> bool: ...

    def isNotYetDefined(self) -> bool: ...

    def isZeroLength(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def removeParent(self, dt: ghidra.program.model.data.DataType) -> None: ...

    def replaceWith(self, dataType: ghidra.program.model.data.DataType) -> None: ...

    def setCategoryPath(self, path: ghidra.program.model.data.CategoryPath) -> None: ...

    def setDefaultSettings(self, settings: ghidra.docking.settings.Settings) -> None: ...

    def setDescription(self, description: unicode) -> None:
        """
        Sets a String briefly describing this DataType.
         <br>If a data type that extends this class wants to allow the description to be changed,
         then it must override this method.
        @param description a one-liner describing this DataType.
        @throws UnsupportedOperationException if the description is not allowed to be set for this data type.
        """
        ...

    def setLastChangeTime(self, lastChangeTime: long) -> None: ...

    def setLastChangeTimeInSourceArchive(self, lastChangeTimeInSourceArchive: long) -> None: ...

    def setName(self, name: unicode) -> None: ...

    def setNameAndCategory(self, path: ghidra.program.model.data.CategoryPath, name: unicode) -> None: ...

    def setSourceArchive(self, archive: ghidra.program.model.data.SourceArchive) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def defaultLabelPrefix(self) -> unicode: ...

    @property
    def description(self) -> unicode: ...

    @description.setter
    def description(self, value: unicode) -> None: ...