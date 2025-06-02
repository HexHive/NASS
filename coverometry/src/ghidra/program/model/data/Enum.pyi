from typing import List
import ghidra.docking.settings
import ghidra.program.database.data
import ghidra.program.model.data
import ghidra.program.model.mem
import ghidra.util
import java.lang
import java.net
import java.util


class Enum(ghidra.program.model.data.DataType, object):
    CONFLICT_SUFFIX: unicode = u'.conflict'
    DEFAULT: ghidra.program.model.data.DataType = undefined
    NO_LAST_CHANGE_TIME: long = 0x0L
    NO_SOURCE_SYNC_TIME: long = 0x0L
    TYPEDEF_ATTRIBUTE_PREFIX: unicode = u'__(('
    TYPEDEF_ATTRIBUTE_SUFFIX: unicode = u'))'
    VOID: ghidra.program.model.data.DataType = void







    @overload
    def add(self, name: unicode, value: long) -> None:
        """
        Add a enum entry.
        @param name name of the new entry
        @param value value of the new entry
        """
        ...

    @overload
    def add(self, name: unicode, value: long, comment: unicode) -> None:
        """
        Add a enum entry.
        @param name name of the new entry
        @param value value of the new entry
        @param comment comment of the new entry
        """
        ...

    def addParent(self, __a0: ghidra.program.model.data.DataType) -> None: ...

    def clone(self, __a0: ghidra.program.model.data.DataTypeManager) -> ghidra.program.model.data.DataType: ...

    @overload
    def contains(self, value: long) -> bool:
        """
        Returns true if this enum has an entry with the given value.
        @param value the value to check for an entry
        @return true if this enum has an entry with the given value
        """
        ...

    @overload
    def contains(self, name: unicode) -> bool:
        """
        Returns true if this enum has an entry with the given name.
        @param name the name to check for an entry
        @return true if this enum has an entry with the given name
        """
        ...

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

    def getComment(self, name: unicode) -> unicode:
        """
        Get the comment for the given name.
        @param name name of the entry.
        @return the comment or the empty string if the name does not exist in this enum or if no
         comment is set.
        """
        ...

    def getCount(self) -> int:
        """
        Get the number of entries in this Enum.
        @return the number of entries in this Enum.
        """
        ...

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

    def getMaxPossibleValue(self) -> long:
        """
        Returns the maximum value that this enum can represent based on its size and signedness.
        @return the maximum value that this enum can represent based on its size and signedness.
        """
        ...

    def getMinPossibleValue(self) -> long:
        """
        Returns the maximum value that this enum can represent based on its size and signedness.
        @return the maximum value that this enum can represent based on its size and signedness.
        """
        ...

    def getMinimumPossibleLength(self) -> int:
        """
        Returns the smallest length (size in bytes) this enum can be and still represent all of
         it's current values. Note that that this will only return powers of 2 (1,2,4, or 8)
        @return the smallest length (size in bytes) this enum can be and still represent all of
         it's current values
        """
        ...

    def getMnemonic(self, __a0: ghidra.docking.settings.Settings) -> unicode: ...

    @overload
    def getName(self) -> unicode: ...

    @overload
    def getName(self, value: long) -> unicode:
        """
        Get the name for the given value.
        @param value value of the enum entry.
        @return null if the name with the given value was not found.
        """
        ...

    @overload
    def getNames(self) -> List[unicode]:
        """
        Get the names of the enum entries.  The returned names are first sorted by the enum int
         value, then sub-sorted by name value where there are multiple name values per int value.
        @return the names of the enum entries.
        """
        ...

    @overload
    def getNames(self, value: long) -> List[unicode]:
        """
        Returns all names that map to the given value.
        @param value value for the enum entries.
        @return all names; null if there is not name for the given value.
        """
        ...

    def getParents(self) -> java.util.Collection: ...

    def getPathName(self) -> unicode: ...

    @overload
    def getRepresentation(self, __a0: ghidra.program.model.mem.MemBuffer, __a1: ghidra.docking.settings.Settings, __a2: int) -> unicode: ...

    @overload
    def getRepresentation(self, bigInt: long, settings: ghidra.docking.settings.Settings, bitLength: int) -> unicode:
        """
        Get enum representation of the big-endian value.
        @param bigInt BigInteger value with the appropriate sign
        @param settings integer format settings (PADDING, FORMAT, etc.)
        @param bitLength the bit length
        @return formatted integer string
        """
        ...

    def getSettingsDefinitions(self) -> List[ghidra.docking.settings.SettingsDefinition]: ...

    def getSignedState(self) -> ghidra.program.database.data.EnumSignedState:
        """
        Returns the signed state.
        @return the signed state.
        """
        ...

    def getSourceArchive(self) -> ghidra.program.model.data.SourceArchive: ...

    def getTypeDefSettingsDefinitions(self) -> List[ghidra.program.model.data.TypeDefSettingsDefinition]: ...

    def getUniversalID(self) -> ghidra.util.UniversalID: ...

    @overload
    def getValue(self, name: unicode) -> long:
        """
        Get the value for the given name.
        @param name name of the entry.
        @return the value.
        @throws NoSuchElementException if the name does not exist in this Enum.
        """
        ...

    @overload
    def getValue(self, __a0: ghidra.program.model.mem.MemBuffer, __a1: ghidra.docking.settings.Settings, __a2: int) -> object: ...

    def getValueClass(self, __a0: ghidra.docking.settings.Settings) -> java.lang.Class: ...

    def getValues(self) -> List[long]:
        """
        Get the values of the enum entries.
        @return values sorted in ascending order
        """
        ...

    def hasLanguageDependantLength(self) -> bool: ...

    def hashCode(self) -> int: ...

    def isDeleted(self) -> bool: ...

    def isEncodable(self) -> bool: ...

    def isEquivalent(self, __a0: ghidra.program.model.data.DataType) -> bool: ...

    def isNotYetDefined(self) -> bool: ...

    def isSigned(self) -> bool:
        """
        Returns true if the enum contains at least one negative value. Internally, enums have
         three states, signed, unsigned, and none (can't tell from the values). If any of
         the values are negative, the enum is considered signed. If any of the values are large
         unsigned values (upper bit set), then it is considered unsigned. This method will return
         true if the enum is signed, and false if it is either unsigned or none (meaning that it
         doesn't matter for the values that are contained in the enum.
        @return true if the enum contains at least one negative value
        """
        ...

    def isZeroLength(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def remove(self, name: unicode) -> None:
        """
        Remove the enum entry with the given name.
        @param name name of entry to remove.
        """
        ...

    def removeParent(self, __a0: ghidra.program.model.data.DataType) -> None: ...

    def replaceWith(self, __a0: ghidra.program.model.data.DataType) -> None: ...

    def setCategoryPath(self, __a0: ghidra.program.model.data.CategoryPath) -> None: ...

    def setDescription(self, description: unicode) -> None:
        """
        Set the description for this Enum.
        @param description the description
        """
        ...

    def setLastChangeTime(self, __a0: long) -> None: ...

    def setLastChangeTimeInSourceArchive(self, __a0: long) -> None: ...

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

    @property
    def alignedLength(self) -> int: ...

    @property
    def alignment(self) -> int: ...

    @property
    def categoryPath(self) -> ghidra.program.model.data.CategoryPath: ...

    @categoryPath.setter
    def categoryPath(self, value: ghidra.program.model.data.CategoryPath) -> None: ...

    @property
    def count(self) -> int: ...

    @property
    def dataOrganization(self) -> ghidra.program.model.data.DataOrganization: ...

    @property
    def dataTypeManager(self) -> ghidra.program.model.data.DataTypeManager: ...

    @property
    def dataTypePath(self) -> ghidra.program.model.data.DataTypePath: ...

    @property
    def defaultAbbreviatedLabelPrefix(self) -> unicode: ...

    @property
    def defaultLabelPrefix(self) -> unicode: ...

    @property
    def defaultSettings(self) -> ghidra.docking.settings.Settings: ...

    @property
    def deleted(self) -> bool: ...

    @property
    def description(self) -> unicode: ...

    @description.setter
    def description(self, value: unicode) -> None: ...

    @property
    def displayName(self) -> unicode: ...

    @property
    def docs(self) -> java.net.URL: ...

    @property
    def encodable(self) -> bool: ...

    @property
    def lastChangeTime(self) -> long: ...

    @lastChangeTime.setter
    def lastChangeTime(self, value: long) -> None: ...

    @property
    def lastChangeTimeInSourceArchive(self) -> long: ...

    @lastChangeTimeInSourceArchive.setter
    def lastChangeTimeInSourceArchive(self, value: long) -> None: ...

    @property
    def length(self) -> int: ...

    @property
    def maxPossibleValue(self) -> long: ...

    @property
    def minPossibleValue(self) -> long: ...

    @property
    def minimumPossibleLength(self) -> int: ...

    @property
    def name(self) -> unicode: ...

    @name.setter
    def name(self, value: unicode) -> None: ...

    @property
    def names(self) -> List[unicode]: ...

    @property
    def notYetDefined(self) -> bool: ...

    @property
    def parents(self) -> java.util.Collection: ...

    @property
    def pathName(self) -> unicode: ...

    @property
    def settingsDefinitions(self) -> List[ghidra.docking.settings.SettingsDefinition]: ...

    @property
    def signed(self) -> bool: ...

    @property
    def signedState(self) -> ghidra.program.database.data.EnumSignedState: ...

    @property
    def sourceArchive(self) -> ghidra.program.model.data.SourceArchive: ...

    @sourceArchive.setter
    def sourceArchive(self, value: ghidra.program.model.data.SourceArchive) -> None: ...

    @property
    def typeDefSettingsDefinitions(self) -> List[ghidra.program.model.data.TypeDefSettingsDefinition]: ...

    @property
    def universalID(self) -> ghidra.util.UniversalID: ...

    @property
    def values(self) -> List[long]: ...

    @property
    def zeroLength(self) -> bool: ...