from typing import List
import db
import ghidra.docking.settings
import ghidra.framework.model
import ghidra.program.database.map
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.util
import ghidra.util.task
import java.lang
import java.util


class ProgramBasedDataTypeManager(ghidra.program.model.data.DomainFileBasedDataTypeManager, object):
    """
    Extends DataTypeManager to include methods specific to a data type manager for
     a program.
    """

    BAD_DATATYPE_ID: long = -0x2L
    BUILT_IN_ARCHIVE_KEY: long = 0x1L
    BUILT_IN_ARCHIVE_UNIVERSAL_ID: ghidra.util.UniversalID = 1
    BUILT_IN_DATA_TYPES_NAME: unicode = u'BuiltInTypes'
    DEFAULT_DATATYPE_ID: long = 0x0L
    LOCAL_ARCHIVE_KEY: long = 0x0L
    LOCAL_ARCHIVE_UNIVERSAL_ID: ghidra.util.UniversalID = 0
    NULL_DATATYPE_ID: long = -0x1L







    def addDataType(self, __a0: ghidra.program.model.data.DataType, __a1: ghidra.program.model.data.DataTypeConflictHandler) -> ghidra.program.model.data.DataType: ...

    def addDataTypeManagerListener(self, __a0: ghidra.program.model.data.DataTypeManagerChangeListener) -> None: ...

    def addDataTypes(self, __a0: java.util.Collection, __a1: ghidra.program.model.data.DataTypeConflictHandler, __a2: ghidra.util.task.TaskMonitor) -> None: ...

    def addInvalidatedListener(self, __a0: ghidra.program.model.data.InvalidatedListener) -> None: ...

    def allowsDefaultBuiltInSettings(self) -> bool: ...

    def allowsDefaultComponentSettings(self) -> bool: ...

    def associateDataTypeWithArchive(self, __a0: ghidra.program.model.data.DataType, __a1: ghidra.program.model.data.SourceArchive) -> None: ...

    def clearAllSettings(self, data: ghidra.program.model.listing.Data) -> None:
        """
        Clear all settings for the given data.
        @param data data code unit
        """
        ...

    def clearSetting(self, data: ghidra.program.model.listing.Data, name: unicode) -> bool:
        """
        Clear the specified setting for the given data
        @param data data code unit
        @param name settings name
        @return true if the settings were cleared
        """
        ...

    def close(self) -> None: ...

    def contains(self, __a0: ghidra.program.model.data.DataType) -> bool: ...

    def containsCategory(self, __a0: ghidra.program.model.data.CategoryPath) -> bool: ...

    def createCategory(self, __a0: ghidra.program.model.data.CategoryPath) -> ghidra.program.model.data.Category: ...

    def deleteAddressRange(self, startAddr: ghidra.program.model.address.Address, endAddr: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor) -> None:
        """
        Removes all settings in the range
        @param startAddr the first address in the range.
        @param endAddr the last address in the range.
        @param monitor the progress monitor
        @throws CancelledException if the user cancelled the operation.
        """
        ...

    def disassociate(self, __a0: ghidra.program.model.data.DataType) -> None: ...

    def endTransaction(self, __a0: int, __a1: bool) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def findDataType(self, __a0: unicode) -> ghidra.program.model.data.DataType: ...

    def findDataTypeForID(self, __a0: ghidra.util.UniversalID) -> ghidra.program.model.data.DataType: ...

    @overload
    def findDataTypes(self, __a0: unicode, __a1: List[object]) -> None: ...

    @overload
    def findDataTypes(self, __a0: unicode, __a1: List[object], __a2: bool, __a3: ghidra.util.task.TaskMonitor) -> None: ...

    def findEnumValueNames(self, __a0: long, __a1: java.util.Set) -> None: ...

    def flushEvents(self) -> None: ...

    def getAddressMap(self) -> ghidra.program.database.map.AddressMap: ...

    def getAllComposites(self) -> java.util.Iterator: ...

    @overload
    def getAllDataTypes(self) -> java.util.Iterator: ...

    @overload
    def getAllDataTypes(self, __a0: List[object]) -> None: ...

    def getAllFunctionDefinitions(self) -> java.util.Iterator: ...

    def getAllStructures(self) -> java.util.Iterator: ...

    def getCallingConvention(self, __a0: unicode) -> ghidra.program.model.lang.PrototypeModel: ...

    @overload
    def getCategory(self, __a0: long) -> ghidra.program.model.data.Category: ...

    @overload
    def getCategory(self, __a0: ghidra.program.model.data.CategoryPath) -> ghidra.program.model.data.Category: ...

    def getCategoryCount(self) -> int: ...

    def getClass(self) -> java.lang.Class: ...

    def getDataOrganization(self) -> ghidra.program.model.data.DataOrganization: ...

    @overload
    def getDataType(self, __a0: long) -> ghidra.program.model.data.DataType: ...

    @overload
    def getDataType(self, __a0: unicode) -> ghidra.program.model.data.DataType: ...

    @overload
    def getDataType(self, __a0: ghidra.program.model.data.DataTypePath) -> ghidra.program.model.data.DataType: ...

    @overload
    def getDataType(self, __a0: ghidra.program.model.data.CategoryPath, __a1: unicode) -> ghidra.program.model.data.DataType: ...

    @overload
    def getDataType(self, __a0: ghidra.program.model.data.SourceArchive, __a1: ghidra.util.UniversalID) -> ghidra.program.model.data.DataType: ...

    def getDataTypeCount(self, __a0: bool) -> int: ...

    def getDataTypes(self, __a0: ghidra.program.model.data.SourceArchive) -> List[object]: ...

    def getDataTypesContaining(self, __a0: ghidra.program.model.data.DataType) -> java.util.Set: ...

    def getDefaultCallingConvention(self) -> ghidra.program.model.lang.PrototypeModel: ...

    def getDefinedCallingConventionNames(self) -> java.util.Collection: ...

    def getDomainFile(self) -> ghidra.framework.model.DomainFile: ...

    def getFavorites(self) -> List[object]: ...

    def getID(self, __a0: ghidra.program.model.data.DataType) -> long: ...

    def getInstanceSettingsNames(self, data: ghidra.program.model.listing.Data) -> List[unicode]:
        """
        Returns all the instance Settings names used for the specified data
        @param data data code unit
        @return the names
        """
        ...

    def getKnownCallingConventionNames(self) -> java.util.Collection: ...

    def getLastChangeTimeForMyManager(self) -> long: ...

    def getLocalSourceArchive(self) -> ghidra.program.model.data.SourceArchive: ...

    def getLongSettingsValue(self, data: ghidra.program.model.listing.Data, name: unicode) -> long:
        """
        Get the long value for data instance settings.
        @param data data code unit
        @param name settings name
        @return null if the named setting was not found
        """
        ...

    def getName(self) -> unicode: ...

    def getPath(self) -> unicode: ...

    @overload
    def getPointer(self, __a0: ghidra.program.model.data.DataType) -> ghidra.program.model.data.Pointer: ...

    @overload
    def getPointer(self, __a0: ghidra.program.model.data.DataType, __a1: int) -> ghidra.program.model.data.Pointer: ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Get the program instance associated with this datatype manager
        @return program instance associated with this datatype manager
        """
        ...

    def getProgramArchitecture(self) -> ghidra.program.model.lang.ProgramArchitecture: ...

    def getProgramArchitectureSummary(self) -> unicode: ...

    def getResolvedID(self, __a0: ghidra.program.model.data.DataType) -> long: ...

    def getRootCategory(self) -> ghidra.program.model.data.Category: ...

    def getSettings(self, data: ghidra.program.model.listing.Data, name: unicode) -> object:
        """
        Gets the value for data instance settings in Object form.
        @param data data code unit
        @param name the name of settings.
        @return the settings object
        """
        ...

    def getSourceArchive(self, __a0: ghidra.util.UniversalID) -> ghidra.program.model.data.SourceArchive: ...

    def getSourceArchives(self) -> List[object]: ...

    def getStringSettingsValue(self, data: ghidra.program.model.listing.Data, name: unicode) -> unicode:
        """
        Get the String value for data instance settings.
        @param data data code unit
        @param name settings name
        @return null if the named setting was not found
        """
        ...

    def getType(self) -> ghidra.program.model.data.ArchiveType: ...

    def getUniqueName(self, __a0: ghidra.program.model.data.CategoryPath, __a1: unicode) -> unicode: ...

    def getUniversalID(self) -> ghidra.util.UniversalID: ...

    def hashCode(self) -> int: ...

    def isChangeAllowed(self, data: ghidra.program.model.listing.Data, settingsDefinition: ghidra.docking.settings.SettingsDefinition) -> bool:
        """
        Determine if a settings change is permitted for the specified settingsDefinition.
        @param data data code unit
        @param settingsDefinition settings definition
        @return true if change permitted else false
        """
        ...

    def isEmptySetting(self, data: ghidra.program.model.listing.Data) -> bool:
        """
        Returns true if no settings are set for the given data
        @param data data code unit
        @return true if not settings
        """
        ...

    def isFavorite(self, __a0: ghidra.program.model.data.DataType) -> bool: ...

    def isUpdatable(self) -> bool: ...

    def moveAddressRange(self, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, length: long, monitor: ghidra.util.task.TaskMonitor) -> None:
        """
        Move the settings in the range to the new start address
        @param fromAddr start address from where to move
        @param toAddr new Address to move to
        @param length number of addresses to move
        @param monitor progress monitor
        @throws CancelledException if the operation was cancelled
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def openTransaction(self, __a0: unicode) -> db.Transaction: ...

    def remove(self, __a0: ghidra.program.model.data.DataType, __a1: ghidra.util.task.TaskMonitor) -> bool: ...

    def removeDataTypeManagerListener(self, __a0: ghidra.program.model.data.DataTypeManagerChangeListener) -> None: ...

    def removeInvalidatedListener(self, __a0: ghidra.program.model.data.InvalidatedListener) -> None: ...

    def removeSourceArchive(self, __a0: ghidra.program.model.data.SourceArchive) -> None: ...

    def replaceDataType(self, __a0: ghidra.program.model.data.DataType, __a1: ghidra.program.model.data.DataType, __a2: bool) -> ghidra.program.model.data.DataType: ...

    def resolve(self, __a0: ghidra.program.model.data.DataType, __a1: ghidra.program.model.data.DataTypeConflictHandler) -> ghidra.program.model.data.DataType: ...

    def resolveSourceArchive(self, __a0: ghidra.program.model.data.SourceArchive) -> ghidra.program.model.data.SourceArchive: ...

    def setFavorite(self, __a0: ghidra.program.model.data.DataType, __a1: bool) -> None: ...

    def setLongSettingsValue(self, data: ghidra.program.model.listing.Data, name: unicode, value: long) -> bool:
        """
        Set the long value for data instance settings.
        @param data data code unit
        @param name settings name
        @param value value of setting
        @return true if the settings actually changed
        """
        ...

    def setName(self, __a0: unicode) -> None: ...

    def setSettings(self, data: ghidra.program.model.listing.Data, name: unicode, value: object) -> bool:
        """
        Set the Object value for data instance settings.
        @param data data code unit
        @param name the name of the settings
        @param value the value for the settings, must be either a String, byte[]
                         or Long
        @return true if the settings were updated
        """
        ...

    def setStringSettingsValue(self, data: ghidra.program.model.listing.Data, name: unicode, value: unicode) -> bool:
        """
        Set the string value for data instance settings.
        @param data data code unit
        @param name settings name
        @param value value of setting
        @return true if the settings actually changed
        """
        ...

    def startTransaction(self, __a0: unicode) -> int: ...

    def toString(self) -> unicode: ...

    @overload
    def updateSourceArchiveName(self, __a0: unicode, __a1: unicode) -> bool: ...

    @overload
    def updateSourceArchiveName(self, __a0: ghidra.util.UniversalID, __a1: unicode) -> bool: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def addressMap(self) -> ghidra.program.database.map.AddressMap: ...

    @property
    def allComposites(self) -> java.util.Iterator: ...

    @property
    def allDataTypes(self) -> java.util.Iterator: ...

    @property
    def allFunctionDefinitions(self) -> java.util.Iterator: ...

    @property
    def allStructures(self) -> java.util.Iterator: ...

    @property
    def categoryCount(self) -> int: ...

    @property
    def dataOrganization(self) -> ghidra.program.model.data.DataOrganization: ...

    @property
    def defaultCallingConvention(self) -> ghidra.program.model.lang.PrototypeModel: ...

    @property
    def definedCallingConventionNames(self) -> java.util.Collection: ...

    @property
    def domainFile(self) -> ghidra.framework.model.DomainFile: ...

    @property
    def favorites(self) -> List[object]: ...

    @property
    def knownCallingConventionNames(self) -> java.util.Collection: ...

    @property
    def lastChangeTimeForMyManager(self) -> long: ...

    @property
    def localSourceArchive(self) -> ghidra.program.model.data.SourceArchive: ...

    @property
    def name(self) -> unicode: ...

    @name.setter
    def name(self, value: unicode) -> None: ...

    @property
    def path(self) -> unicode: ...

    @property
    def program(self) -> ghidra.program.model.listing.Program: ...

    @property
    def programArchitecture(self) -> ghidra.program.model.lang.ProgramArchitecture: ...

    @property
    def programArchitectureSummary(self) -> unicode: ...

    @property
    def rootCategory(self) -> ghidra.program.model.data.Category: ...

    @property
    def sourceArchives(self) -> List[object]: ...

    @property
    def type(self) -> ghidra.program.model.data.ArchiveType: ...

    @property
    def universalID(self) -> ghidra.util.UniversalID: ...

    @property
    def updatable(self) -> bool: ...