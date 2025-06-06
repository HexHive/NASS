from typing import List
import ghidra.docking.settings
import ghidra.program.model.data
import ghidra.program.model.mem
import ghidra.util
import java.lang
import java.net
import java.util


class DataType(object):
    """
    The interface that all datatypes must implement.
    """

    CONFLICT_SUFFIX: unicode = u'.conflict'
    DEFAULT: ghidra.program.model.data.DataType = undefined
    NO_LAST_CHANGE_TIME: long = 0x0L
    NO_SOURCE_SYNC_TIME: long = 0x0L
    TYPEDEF_ATTRIBUTE_PREFIX: unicode = u'__(('
    TYPEDEF_ATTRIBUTE_SUFFIX: unicode = u'))'
    VOID: ghidra.program.model.data.DataType = void







    def addParent(self, dt: ghidra.program.model.data.DataType) -> None:
        """
        Inform this data type that it has the given parent
         <br>
         TODO: This method is reserved for internal DB use.
        @param dt parent data type
        """
        ...

    def clone(self, dtm: ghidra.program.model.data.DataTypeManager) -> ghidra.program.model.data.DataType:
        """
        Returns an instance of this DataType using the specified {@link DataTypeManager} to allow
         its use of the corresponding {@link DataOrganization} while retaining its unique identity
         (see {@link #getUniversalID()} and archive association (see {@link #getSourceArchive()}) if
         applicable.
         <p>
         This instance will be returned if this datatype's DataTypeManager matches the
         specified dtm. The recursion depth of a clone will stop on any datatype whose
         {@link DataTypeManager} matches the specified dtm and simply use the existing datatype
         instance.
         <p>
         NOTE: In general, this method should not be used to obtain an instance to be modified.
         In most cases changes may be made directly to this instance if supported or to a
         {@link #copy(DataTypeManager)} of this type.
        @param dtm the data-type manager instance whose data-organization should apply.
        @return cloned instance which may be the same as this instance
        """
        ...

    def copy(self, dtm: ghidra.program.model.data.DataTypeManager) -> ghidra.program.model.data.DataType:
        """
        Returns a new instance (shallow copy) of this DataType with a new identity and no
         source archive association.
         <p>
         Any reference to other datatypes will use {@link #clone(DataTypeManager)}.
        @param dtm the data-type manager instance whose data-organization should apply.
        @return new instanceof of this datatype
        """
        ...

    def dataTypeAlignmentChanged(self, dt: ghidra.program.model.data.DataType) -> None:
        """
        Notification that the given datatype's alignment has changed.
         <p>
         DataTypes may need to make internal changes in response. <br>
         TODO: This method is reserved for internal DB use. <br>
        @param dt the datatype that has changed.
        """
        ...

    def dataTypeDeleted(self, dt: ghidra.program.model.data.DataType) -> None:
        """
        Informs this datatype that the given datatype has been deleted.
         <p>
         TODO: This method is reserved for internal DB use. <br>
        @param dt the datatype that has been deleted.
        """
        ...

    def dataTypeNameChanged(self, dt: ghidra.program.model.data.DataType, oldName: unicode) -> None:
        """
        Informs this datatype that its name has changed from the indicated old name.
         <p>
         TODO: This method is reserved for internal DB use. <br>
        @param dt the datatype whose name changed
        @param oldName the datatype's old name
        """
        ...

    def dataTypeReplaced(self, oldDt: ghidra.program.model.data.DataType, newDt: ghidra.program.model.data.DataType) -> None:
        """
        Informs this datatype that the given oldDT has been replaced with newDT
         <p>
         TODO: This method is reserved for internal DB use. <br>
        @param oldDt old datatype
        @param newDt new datatype
        """
        ...

    def dataTypeSizeChanged(self, dt: ghidra.program.model.data.DataType) -> None:
        """
        Notification that the given datatype's size has changed.
         <p>
         DataTypes may need to make internal changes in response. <br>
         TODO: This method is reserved for internal DB use. <br>
        @param dt the datatype that has changed.
        """
        ...

    def dependsOn(self, dt: ghidra.program.model.data.DataType) -> bool:
        """
        Check if this datatype depends on the existence of the given datatype.
         <p>
         For example byte[] depends on byte. If byte were deleted, then byte[] would also be deleted.
        @param dt the datatype to test that this datatype depends on.
        @return true if the existence of this datatype relies on the existence of the specified
                 datatype dt.
        """
        ...

    def encodeRepresentation(self, repr: unicode, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: int) -> List[int]:
        """
        Encode bytes according to the display format for this type.
         <p>
         Converts the given representation to the byte encoding and returns it. When appropriate, this
         should seek the nearest encoding to the specified value, since the representation is likely
         coming from user input. For example, a floating-point value may be rounded. Invalid
         representations should be rejected with a {@link DataTypeEncodeException}.
        @param repr the representation of the desired value, as in
                    {@link #getRepresentation(MemBuffer, Settings, int)}. The supported formats depend
                    on the specific datatype and its settings.
        @param buf a buffer representing the eventual destination of the bytes.
        @param settings the settings to use for the representation.
        @param length the expected length of the result, usually the length of the data unit, or -1
                    to let the type choose the length. It may be ignored, e.g., for fixed-length
                    types.
        @return the encoded value.
        @throws DataTypeEncodeException if the value cannot be encoded for any reason, e.g.,
                     incorrect format, not enough space, buffer overflow, unsupported (see
                     {@link #isEncodable()}).
        """
        ...

    def encodeValue(self, value: object, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: int) -> List[int]:
        """
        Encode bytes from an Object appropriate for this DataType.
         <p>
         Converts the given object to the byte encoding and returns it. When appropriate, this should
         seek the nearest encoding to the specified value, since the object may come from a user
         script. For example, a floating-point value may be rounded. Invalid values should be rejected
         with a {@link DataTypeEncodeException}.
        @param value the desired value.
        @param buf a buffer representing the eventual destination of the bytes.
        @param settings the settings to use.
        @param length the expected length of the result, usually the length of the data unit, or -1
                    to let the type choose the length. It may be ignored, e.g., for fixed-length
                    types.
        @return the encoded value.
        @throws DataTypeEncodeException if the value cannot be encoded for any reason, e.g.,
                     incorrect type, not enough space, buffer overflow, unsupported (see
                     {@link #isEncodable()}).
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getAlignedLength(self) -> int:
        """
        Get the aligned-length of this datatype as a number of 8-bit bytes. 
         <p>
         For primitive datatypes this is equivalent to the C/C++ "sizeof" operation within source code and
         should be used when determining {@link Array} element length or component sizing for  a 
         {@link Composite}.   For {@link Pointer}, {@link Composite} and {@link Array} types this will 
         return the same value as {@link #getLength()}. 
         <p>
         Example: For x86 32-bit gcc an 80-bit {@code long double} {@link #getLength() raw data length} 
         of 10-bytes will fit within a floating point register while its {@link #getAlignedLength() aligned-length}  
         of 12-bytes is used by the gcc compiler for data/array/component allocations to maintain alignment 
         (i.e., {@code sizeof(long double)} ).
         <p>
         NOTE: Other than the {@link VoidDataType}, no datatype should ever return 0, even if 
         {@link #isZeroLength()}, and only {@link Dynamic} / {@link FactoryDataType} /
         {@link FunctionDefinition} datatypes should return -1.  If {@link #isZeroLength()} is true 
         a length of 1 should be returned.
        @return byte length of binary encoding.
        """
        ...

    def getAlignment(self) -> int:
        """
        Gets the alignment to be used when aligning this datatype within another datatype.
        @return this datatype's alignment.
        """
        ...

    def getCategoryPath(self) -> ghidra.program.model.data.CategoryPath:
        """
        Gets the categoryPath associated with this datatype
        @return the datatype's category path
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getDataOrganization(self) -> ghidra.program.model.data.DataOrganization:
        """
        Returns the DataOrganization associated with this data-type
        @return associated data organization
        """
        ...

    def getDataTypeManager(self) -> ghidra.program.model.data.DataTypeManager:
        """
        Get the DataTypeManager containing this datatype.
         <p>
         This association should not be used to indicate whether this DataType has been resolved, but
         is intended to indicate whether the appropriate DataOrganization is being used.
        @return the DataTypeManager that is associated with this datatype.
        """
        ...

    def getDataTypePath(self) -> ghidra.program.model.data.DataTypePath:
        """
        Returns the dataTypePath for this datatype;
        @return the dataTypePath for this datatype;
        """
        ...

    def getDefaultAbbreviatedLabelPrefix(self) -> unicode:
        """
        Returns the prefix to use for this datatype when an abbreviated prefix is desired.
         <p>
         For example, some datatypes will built a large default label, at which is is more desirable
         to have a shortened prefix.
        @return the prefix to use for this datatype when an abbreviated prefix is desired. May return
                 null.
        """
        ...

    @overload
    def getDefaultLabelPrefix(self) -> unicode:
        """
        Returns the appropriate string to use as the default label prefix in the absence of any data.
        @return the default label prefix or null if none specified.
        """
        ...

    @overload
    def getDefaultLabelPrefix(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, len: int, options: ghidra.program.model.data.DataTypeDisplayOptions) -> unicode:
        """
        Returns the appropriate string to use as the default label prefix.
        @param buf memory buffer containing the bytes.
        @param settings the Settings object
        @param len the length of the data.
        @param options options for how to format the default label prefix.
        @return the default label prefix or null if none specified.
        """
        ...

    def getDefaultOffcutLabelPrefix(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, len: int, options: ghidra.program.model.data.DataTypeDisplayOptions, offcutOffset: int) -> unicode:
        """
        Returns the appropriate string to use as the default label prefix.
         <p>
         This takes into account the fact that there exists a reference to the data that references
         <code>offcutLength</code> bytes into this type
        @param buf memory buffer containing the bytes.
        @param settings the Settings object
        @param len the length of the data.
        @param options options for how to format the default label prefix.
        @param offcutOffset offset into datatype
        @return the default label prefix.
        """
        ...

    def getDefaultSettings(self) -> ghidra.docking.settings.Settings:
        """
        Gets the settings for this data type.  The settings may have underlying default settings
         and may in turn become defaults for instance-specific settings (e.g., Data or DataTypeComponent).
         It is important to note that these settings are tied to a specific DataType instantiation
         so it is important to understand the scope of its use.  Example: The {@link BuiltInDataTypeManager}
         has its own set of DataType instances which are separate from those which have been instantiated
         or resolved to a specific Program/Archive {@link DataTypeManager}. Settings manipulation may
         be disabled by default in some instances.
        @return the settings for this dataType.
        """
        ...

    def getDescription(self) -> unicode:
        """
        Get a String briefly describing this DataType.
        @return a one-liner describing this DataType.
        """
        ...

    def getDisplayName(self) -> unicode:
        """
        Gets the name for referring to this datatype.
        @return generic name for this Data Type (i.e.: Word)
        """
        ...

    def getDocs(self) -> java.net.URL:
        """
        The getDocs method should provide a URL pointing to extended documentation for this DataType
         if it exists.
         <p>
         A typical use would be to return a URL pointing to the programmers reference for this
         instruction or a page describing this data structure.
        @return null - there is no URL documentation for this prototype.
        """
        ...

    def getLastChangeTime(self) -> long:
        """
        Get the timestamp corresponding to the last time this type was changed within its datatype
         manager
        @return timestamp of last change within datatype manager
        """
        ...

    def getLastChangeTimeInSourceArchive(self) -> long:
        """
        Get the timestamp corresponding to the last time this type was sync'd within its source
         archive
        @return timestamp of last sync with source archive
        """
        ...

    def getLength(self) -> int:
        """
        Get the length of this DataType as a number of 8-bit bytes. 
         <p>
         For primitive datatypes this reflects the smallest varnode which can be used to
         contain its value (i.e., raw data length).  
         <p>
         Example: For x86 32-bit gcc an 80-bit {@code long double} {@link #getLength() raw data length} 
         of 10-bytes will fit within a floating point register while its {@link #getAlignedLength() aligned-length} 
         of 12-bytes is used by the gcc compiler for data/array/component allocations to maintain alignment 
         (i.e., {@code sizeof(long double)} ).
         <p>
         NOTE: Other than the {@link VoidDataType}, no datatype should ever return 0, even if 
         {@link #isZeroLength()}, and only {@link Dynamic}/{@link FactoryDataType} datatypes 
         should return -1.  If {@link #isZeroLength()} is true a length of 1 should be returned. 
         Where a zero-length datatype can be handled (e.g., {@link Composite}) the 
         {@link #isZeroLength()} method should be used.
        @return the length of this DataType
        """
        ...

    def getMnemonic(self, settings: ghidra.docking.settings.Settings) -> unicode:
        """
        Get the mnemonic for this DataType.
        @param settings settings which may influence the result or null
        @return the mnemonic for this DataType.
        """
        ...

    def getName(self) -> unicode:
        """
        Get the name of this datatype.
        @return the name
        """
        ...

    def getParents(self) -> java.util.Collection:
        """
        Get the parents of this datatype.

         NOTE: This method is intended to be used on a DB-managed datatype only and is not
         fully supported for use with non-DB datatype instances.
        @return parents of this datatype
        """
        ...

    def getPathName(self) -> unicode:
        """
        Get the full category path name that includes this datatype's name.
         <p>
         If the category is null, then this just the datatype's name is returned.
        @return the path, or just this type's name
        """
        ...

    def getRepresentation(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: int) -> unicode:
        """
        Get bytes from memory in a printable format for this type.
        @param buf the data.
        @param settings the settings to use for the representation.
        @param length the number of bytes to represent.
        @return the representation of the data in this format, never null.
        """
        ...

    def getSettingsDefinitions(self) -> List[ghidra.docking.settings.SettingsDefinition]:
        """
        Get the list of settings definitions available for use with this datatype.
         <p>
         In the case of a {@link TypeDef}, the return list will include the
         {@link TypeDefSettingsDefinition} list from the associated base data type.
         <p>
         Unlike {@link TypeDefSettingsDefinition} standard settings definitions
         generally support default, component-default and data-instance use.
         In addition, standard settings definitions are never considered during
         {@link #isEquivalent(DataType)} checking or during the resolve process.
        @return list of the settings definitions for this datatype.
        """
        ...

    def getSourceArchive(self) -> ghidra.program.model.data.SourceArchive:
        """
        Get the source archive where this type originated
        @return source archive object
        """
        ...

    def getTypeDefSettingsDefinitions(self) -> List[ghidra.program.model.data.TypeDefSettingsDefinition]:
        """
        Get the list of all settings definitions for this datatype that may be
         used for an associated {@link TypeDef}.  When used for an associated
         {@link TypeDef}, these settings will be considered during a
         {@link TypeDef#isEquivalent(DataType)} check and will be preserved
         during the resolve process.
        @return a list of the settings definitions for a {@link TypeDef}
         associated with this datatype.
        """
        ...

    def getUniversalID(self) -> ghidra.util.UniversalID:
        """
        Get the universal ID for this datatype.
         <p>
         This value is intended to be a unique identifier across all programs and archives. The same
         ID indicates that two datatypes were originally the same one. Keep in mind names, categories,
         and component makeup may differ and have changed since there origin.
        @return datatype UniversalID
        """
        ...

    def getValue(self, buf: ghidra.program.model.mem.MemBuffer, settings: ghidra.docking.settings.Settings, length: int) -> object:
        """
        Returns the interpreted data value as an instance of the 
         {@link #getValueClass(Settings) advertised value class}.
         <p>
         For instance, {@link Pointer} data types should return an Address object (or null), or
         integer data types should return a {@link Scalar} object.
        @param buf the data buffer
        @param settings the settings to use.
        @param length indicates the maximum number of bytes that may be consumed by a 
         {@link Dynamic} datatype, otherwise this value is ignored.  A value of -1 may be specified
         to allow a Dynamic datatype to determine the length based upon the actual data bytes
        @return the data object, or null if data is invalid
        """
        ...

    def getValueClass(self, settings: ghidra.docking.settings.Settings) -> java.lang.Class:
        """
        Get the Class of the value Object to be returned by this datatype
         (see {@link #getValue(MemBuffer, Settings, int)}).
        @param settings the relevant settings to use or null for default.
        @return Class of the value to be returned by this datatype or null if it can vary or is
                 unspecified. Types which correspond to a string or char array will return the String
                 class.
        """
        ...

    def hasLanguageDependantLength(self) -> bool:
        """
        Indicates if the length of this data-type is determined based upon the
         {@link DataOrganization} obtained from the associated {@link DataTypeManager}.
        @return true length is language/compiler-specification dependent, else false
        """
        ...

    def hashCode(self) -> int: ...

    def isDeleted(self) -> bool:
        """
        Returns true if this datatype has been deleted and is no longer valid
        @return true if this datatype has been deleted and is no longer valid.
        """
        ...

    def isEncodable(self) -> bool:
        """
        Check if this type supports encoding (patching)
         <p>
         If unsupported, {@link #encodeValue(Object, MemBuffer, Settings, int)} and
         {@link #encodeRepresentation(String, MemBuffer, Settings, int)} will always throw an
         exception. Actions which rely on either {@code encode} method should not be displayed if the
         applicable datatype is not encodable.
        @return true if encoding is supported
        """
        ...

    def isEquivalent(self, dt: ghidra.program.model.data.DataType) -> bool:
        """
        Check if the given datatype is equivalent to this datatype.
         <p>
         The precise meaning of "equivalent" is datatype dependent. <br>
         NOTE: if invoked by a DB object or manager it should be invoked on the DataTypeDB object
         passing the other datatype as the argument.
        @param dt the datatype being tested for equivalence.
        @return true if the if the given datatype is equivalent to this datatype.
        """
        ...

    def isNotYetDefined(self) -> bool:
        """
        Indicates if this datatype has not yet been fully defined.
         <p>
         Such datatypes should always return a {@link #getLength()} of 1 and true for
         {@link #isZeroLength()}. (example: empty structure)
        @return true if this type is not yet defined.
        """
        ...

    def isZeroLength(self) -> bool:
        """
        Indicates this datatype is defined with a zero length.
         <p>
         This method should not be confused with {@link #isNotYetDefined()} which indicates that
         nothing but the name and basic type is known.
         <p>
         NOTE: a zero-length datatype must return a length of 1 via {@link #getLength()}. Zero-length
         datatypes used as a component within a {@link Composite} may, or may not, be assigned a
         component length of 0. The method {@link DataTypeComponent#usesZeroLengthComponent(DataType)}
         is used to make this determination.
        @return true if type definition has a length of 0, else false
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def removeParent(self, dt: ghidra.program.model.data.DataType) -> None:
        """
        Remove a parent datatype
         <p>
         TODO: This method is reserved for internal DB use. <br>
        @param dt parent datatype
        """
        ...

    def replaceWith(self, dataType: ghidra.program.model.data.DataType) -> None:
        """
        For datatypes that support change, this method replaces the internals of this datatype with
         the internals of the given datatype.
         <p>
         The datatypes must be of the same "type" (i.e. structure can only be replacedWith another
         structure.
        @param dataType the datatype that contains the internals to upgrade to.
        @throws UnsupportedOperationException if the datatype does not support change.
        @throws IllegalArgumentException if the given datatype is not the same type as this datatype.
        """
        ...

    def setCategoryPath(self, path: ghidra.program.model.data.CategoryPath) -> None:
        """
        Set the categoryPath associated with this datatype
        @param path the new path
        @throws DuplicateNameException if an attempt to place this datatype into the specified
                     category resulted in a name collision. This should not occur for non-DB DataType
                     instances.
        """
        ...

    def setDescription(self, description: unicode) -> None:
        """
        Sets a String briefly describing this DataType.
        @param description a one-liner describing this DataType.
        @throws UnsupportedOperationException if the description is not allowed to be set for this
                     datatype.
        """
        ...

    def setLastChangeTime(self, lastChangeTime: long) -> None:
        """
        Sets the lastChangeTime for this datatype.
         <p>
         Normally, this is updated automatically when a datatype is changed, but when committing or
         updating while synchronizing an archive, the lastChangeTime may need to be updated
         externally.
        @param lastChangeTime the time to use as the lastChangeTime for this datatype
        """
        ...

    def setLastChangeTimeInSourceArchive(self, lastChangeTimeInSourceArchive: long) -> None:
        """
        Sets the lastChangeTimeInSourceArchive for this datatype.
         <p>
         This is used by when a datatype change is committed back to its source archive.
        @param lastChangeTimeInSourceArchive the time to use as the lastChangeTimeInSourceArchive for
                    this datatype
        """
        ...

    def setName(self, name: unicode) -> None:
        """
        Sets the name of the datatype
        @param name the new name for this datatype.
        @throws InvalidNameException if the given name does not form a valid name.
        @throws DuplicateNameException if name change on stored {@link DataType} is a duplicate of
                     another datatype within the same category (only applies to DB stored
                     {@link DataType}).
        """
        ...

    def setNameAndCategory(self, path: ghidra.program.model.data.CategoryPath, name: unicode) -> None:
        """
        Sets the name and category of a datatype at the same time.
        @param path the new category path.
        @param name the new name
        @throws InvalidNameException if the name is invalid
        @throws DuplicateNameException if name change on stored {@link DataType} is a duplicate of
                     another datatype within the same category (only applies to DB stored
                     {@link DataType}).
        """
        ...

    def setSourceArchive(self, archive: ghidra.program.model.data.SourceArchive) -> None:
        """
        Set the source archive where this type originated
        @param archive source archive object
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
    def alignedLength(self) -> int: ...

    @property
    def alignment(self) -> int: ...

    @property
    def categoryPath(self) -> ghidra.program.model.data.CategoryPath: ...

    @categoryPath.setter
    def categoryPath(self, value: ghidra.program.model.data.CategoryPath) -> None: ...

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
    def name(self) -> unicode: ...

    @name.setter
    def name(self, value: unicode) -> None: ...

    @property
    def notYetDefined(self) -> bool: ...

    @property
    def parents(self) -> java.util.Collection: ...

    @property
    def pathName(self) -> unicode: ...

    @property
    def settingsDefinitions(self) -> List[ghidra.docking.settings.SettingsDefinition]: ...

    @property
    def sourceArchive(self) -> ghidra.program.model.data.SourceArchive: ...

    @sourceArchive.setter
    def sourceArchive(self, value: ghidra.program.model.data.SourceArchive) -> None: ...

    @property
    def typeDefSettingsDefinitions(self) -> List[ghidra.program.model.data.TypeDefSettingsDefinition]: ...

    @property
    def universalID(self) -> ghidra.util.UniversalID: ...

    @property
    def zeroLength(self) -> bool: ...