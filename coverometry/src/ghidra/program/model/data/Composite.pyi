from typing import List
import ghidra.docking.settings
import ghidra.program.model.data
import ghidra.program.model.mem
import ghidra.util
import java.lang
import java.net
import java.util


class Composite(ghidra.program.model.data.DataType, object):
    """
    Interface for common methods in Structure and Union
    """

    CONFLICT_SUFFIX: unicode = u'.conflict'
    DEFAULT: ghidra.program.model.data.DataType = undefined
    NO_LAST_CHANGE_TIME: long = 0x0L
    NO_SOURCE_SYNC_TIME: long = 0x0L
    TYPEDEF_ATTRIBUTE_PREFIX: unicode = u'__(('
    TYPEDEF_ATTRIBUTE_SUFFIX: unicode = u'))'
    VOID: ghidra.program.model.data.DataType = void







    @overload
    def add(self, dataType: ghidra.program.model.data.DataType) -> ghidra.program.model.data.DataTypeComponent:
        """
        Adds a new datatype to the end of this composite.  This is the preferred method
         to use for adding components to an aligned structure for fixed-length dataTypes.
        @param dataType the datatype to add.
        @return the DataTypeComponent created.
        @throws IllegalArgumentException if the specified data type is not
         allowed to be added to this composite data type.
         For example, suppose dt1 contains dt2. Therefore it is not valid
         to add dt1 to dt2 since this would cause a cyclic dependency.
        """
        ...

    @overload
    def add(self, dataType: ghidra.program.model.data.DataType, length: int) -> ghidra.program.model.data.DataTypeComponent:
        """
        Adds a new datatype to the end of this composite. This is the preferred method
         to use for adding components to an aligned structure for dynamic dataTypes such as
         strings whose length must be specified.
        @param dataType the datatype to add.
        @param length the length to associate with the datatype.
         For fixed length types a length &lt;= 0 will use the length of the resolved dataType.
        @return the componentDataType created.
        @throws IllegalArgumentException if the specified data type is not
         allowed to be added to this composite data type or an invalid length
         is specified.
         For example, suppose dt1 contains dt2. Therefore it is not valid
         to add dt1 to dt2 since this would cause a cyclic dependency.
        """
        ...

    @overload
    def add(self, dataType: ghidra.program.model.data.DataType, name: unicode, comment: unicode) -> ghidra.program.model.data.DataTypeComponent:
        """
        Adds a new datatype to the end of this composite.  This is the preferred method
         to use for adding components to an aligned structure for fixed-length dataTypes.
        @param dataType the datatype to add.
        @param name the field name to associate with this component.
        @param comment the comment to associate with this component.
        @return the componentDataType created.
        @throws IllegalArgumentException if the specified data type is not
         allowed to be added to this composite data type.
         For example, suppose dt1 contains dt2. Therefore it is not valid
         to add dt1 to dt2 since this would cause a cyclic dependency.
        """
        ...

    @overload
    def add(self, dataType: ghidra.program.model.data.DataType, length: int, name: unicode, comment: unicode) -> ghidra.program.model.data.DataTypeComponent:
        """
        Adds a new datatype to the end of this composite.  This is the preferred method
         to use for adding components to an aligned structure for dynamic dataTypes such as
         strings whose length must be specified.
        @param dataType the datatype to add.
        @param length the length to associate with the datatype.
         For fixed length types a length &lt;= 0 will use the length of the resolved dataType.
        @param name the field name to associate with this component.
        @param comment the comment to associate with this component.
        @return the componentDataType created.
        @throws IllegalArgumentException if the specified data type is not
         allowed to be added to this composite data type or an invalid length is specified.
         For example, suppose dt1 contains dt2. Therefore it is not valid
         to add dt1 to dt2 since this would cause a cyclic dependency.
        """
        ...

    def addBitField(self, baseDataType: ghidra.program.model.data.DataType, bitSize: int, componentName: unicode, comment: unicode) -> ghidra.program.model.data.DataTypeComponent:
        """
        Adds a new bitfield to the end of this composite.  This method is intended
         to be used with packed structures/unions only where the bitfield will be
         appropriately packed.  The minimum storage storage byte size will be applied.
         It will not provide useful results for composites with packing disabled.
        @param baseDataType the bitfield base datatype (certain restrictions apply).
        @param bitSize the bitfield size in bits
        @param componentName the field name to associate with this component.
        @param comment the comment to associate with this component.
        @return the componentDataType created whose associated data type will
         be BitFieldDataType.
        @throws InvalidDataTypeException if the specified data type is
         not a valid base type for bitfields.
        """
        ...

    def addParent(self, __a0: ghidra.program.model.data.DataType) -> None: ...

    def align(self, minAlignment: int) -> None:
        """
        Same as {@link #setExplicitMinimumAlignment(int)}.
        @param minAlignment the explicit minimum alignment for this Composite.
        @throws IllegalArgumentException if a non-positive value is specified
        """
        ...

    def clone(self, __a0: ghidra.program.model.data.DataTypeManager) -> ghidra.program.model.data.DataType: ...

    def copy(self, __a0: ghidra.program.model.data.DataTypeManager) -> ghidra.program.model.data.DataType: ...

    def dataTypeAlignmentChanged(self, dt: ghidra.program.model.data.DataType) -> None:
        """
        The alignment changed for the specified data type.  If packing is enabled for this
         composite, the placement of the component may be affected by a change in its alignment.
         A non-packed composite can ignore this notification.
        @param dt the data type whose alignment changed.
        """
        ...

    def dataTypeDeleted(self, __a0: ghidra.program.model.data.DataType) -> None: ...

    def dataTypeNameChanged(self, __a0: ghidra.program.model.data.DataType, __a1: unicode) -> None: ...

    def dataTypeReplaced(self, __a0: ghidra.program.model.data.DataType, __a1: ghidra.program.model.data.DataType) -> None: ...

    def dataTypeSizeChanged(self, __a0: ghidra.program.model.data.DataType) -> None: ...

    @overload
    def delete(self, ordinal: int) -> None:
        """
        Deletes the component at the given ordinal position.
         <BR>Note: Removal of bitfields from a structure with packing disabled will
         not shift other components causing vacated bytes to revert to undefined filler.
        @param ordinal the ordinal of the component to be deleted.
        @throws IndexOutOfBoundsException if component ordinal is out of bounds
        """
        ...

    @overload
    def delete(self, ordinals: java.util.Set) -> None:
        """
        Deletes the specified set of components at the given ordinal positions.
         <BR>Note: Removal of bitfields from a structure with packing disabled will
         not shift other components causing vacated bytes to revert to undefined filler.
        @param ordinals the ordinals of the component to be deleted.
        @throws IndexOutOfBoundsException if any specified component ordinal is out of bounds
        """
        ...

    def dependsOn(self, __a0: ghidra.program.model.data.DataType) -> bool: ...

    def encodeRepresentation(self, __a0: unicode, __a1: ghidra.program.model.mem.MemBuffer, __a2: ghidra.docking.settings.Settings, __a3: int) -> List[int]: ...

    def encodeValue(self, __a0: object, __a1: ghidra.program.model.mem.MemBuffer, __a2: ghidra.docking.settings.Settings, __a3: int) -> List[int]: ...

    def equals(self, __a0: object) -> bool: ...

    def getAlignedLength(self) -> int: ...

    def getAlignment(self) -> int:
        """
        Get the computed alignment for this composite based upon packing and minimum
         alignment settings as well as component alignment.  If packing is disabled,
         the alignment will always be 1 unless a minimum alignment has been set.
        @return this composites alignment
        """
        ...

    def getAlignmentType(self) -> ghidra.program.model.data.AlignmentType:
        """
        @return the alignment type set for this composite
        """
        ...

    def getCategoryPath(self) -> ghidra.program.model.data.CategoryPath: ...

    def getClass(self) -> java.lang.Class: ...

    def getComponent(self, ordinal: int) -> ghidra.program.model.data.DataTypeComponent:
        """
        Returns the component of this data type with the indicated ordinal.
        @param ordinal the component's ordinal (zero based).
        @return the data type component.
        @throws IndexOutOfBoundsException if the ordinal is out of bounds
        """
        ...

    def getComponents(self) -> List[ghidra.program.model.data.DataTypeComponent]:
        """
        Returns an array of Data Type Components that make up this composite including
         undefined filler components which may be present within a Structure which has packing disabled.
         The number of components corresponds to {@link #getNumComponents()}.
        @return array all components
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

    def getDefinedComponents(self) -> List[ghidra.program.model.data.DataTypeComponent]:
        """
        Returns an array of Data Type Components that make up this composite excluding
         undefined filler components which may be present within Structures where packing is disabled.
         The number of components corresponds to {@link #getNumDefinedComponents()}.  For Unions and
         packed Structures this is equivalent to {@link #getComponents()}
         since they do not contain undefined filler components.
        @return array all explicitly defined components
        """
        ...

    def getDescription(self) -> unicode: ...

    def getDisplayName(self) -> unicode: ...

    def getDocs(self) -> java.net.URL: ...

    def getExplicitMinimumAlignment(self) -> int:
        """
        Get the explicit minimum alignment setting for this Composite which contributes
         to the actual computed alignment value (see {@link #getAlignment()}.
        @return the minimum alignment setting for this Composite or an undefined
         non-positive value if an explicit minimum alignment has not been set.
        """
        ...

    def getExplicitPackingValue(self) -> int:
        """
        Gets the current packing value (typically a power of 2).
         If this isn't a packed composite with an explicit packing value (see {@link #hasExplicitPackingValue()})
         then the return value is undefined.
        @return the current packing value or an undefined non-positive value
        """
        ...

    def getLastChangeTime(self) -> long: ...

    def getLastChangeTimeInSourceArchive(self) -> long: ...

    def getLength(self) -> int: ...

    def getMnemonic(self, __a0: ghidra.docking.settings.Settings) -> unicode: ...

    def getName(self) -> unicode: ...

    def getNumComponents(self) -> int:
        """
        Gets the number of component data types in this composite.
         If this is Structure with packing disabled, the count will include all undefined filler
         components which may be present.
        @return the number of components that make up this composite
        """
        ...

    def getNumDefinedComponents(self) -> int:
        """
        Returns the number of explicitly defined components in this composite.
         For Unions and packed Structures this is equivalent to {@link #getNumComponents()}
         since they do not contain undefined components.
         This count will always exclude all undefined filler components which may be present
         within a Structure whose packing is disabled (see {@link #isPackingEnabled()}).
        @return the number of explicitly defined components in this composite
        """
        ...

    def getPackingType(self) -> ghidra.program.model.data.PackingType:
        """
        @return the packing type set for this composite
        """
        ...

    def getParents(self) -> java.util.Collection: ...

    def getPathName(self) -> unicode: ...

    def getRepresentation(self, __a0: ghidra.program.model.mem.MemBuffer, __a1: ghidra.docking.settings.Settings, __a2: int) -> unicode: ...

    def getSettingsDefinitions(self) -> List[ghidra.docking.settings.SettingsDefinition]: ...

    def getSourceArchive(self) -> ghidra.program.model.data.SourceArchive: ...

    def getTypeDefSettingsDefinitions(self) -> List[ghidra.program.model.data.TypeDefSettingsDefinition]: ...

    def getUniversalID(self) -> ghidra.util.UniversalID: ...

    def getValue(self, __a0: ghidra.program.model.mem.MemBuffer, __a1: ghidra.docking.settings.Settings, __a2: int) -> object: ...

    def getValueClass(self, __a0: ghidra.docking.settings.Settings) -> java.lang.Class: ...

    def hasDefaultPacking(self) -> bool:
        """
        Determine if default packing is enabled.
        @return true if default packing is enabled.
        """
        ...

    def hasExplicitMinimumAlignment(self) -> bool:
        """
        Determine if an explicit minimum alignment has been set (see
         {@link #getExplicitMinimumAlignment()}). An undefined value is returned if default alignment
         or machine alignment is enabled.
        @return true if an explicit minimum alignment has been set, else false
        """
        ...

    def hasExplicitPackingValue(self) -> bool:
        """
        Determine if packing is enabled with an explicit packing value (see {@link #getExplicitPackingValue()}).
        @return true if packing is enabled with an explicit packing value, else false.
        """
        ...

    def hasLanguageDependantLength(self) -> bool: ...

    def hashCode(self) -> int: ...

    @overload
    def insert(self, ordinal: int, dataType: ghidra.program.model.data.DataType) -> ghidra.program.model.data.DataTypeComponent:
        """
        Inserts a new datatype at the specified ordinal position in this composite.
         <BR>Note: For an aligned structure the ordinal position will get adjusted
         automatically to provide the proper alignment.
        @param ordinal the ordinal where the new datatype is to be inserted.
        @param dataType the datatype to insert.
        @return the componentDataType created.
        @throws IllegalArgumentException if the specified data type is not
         allowed to be inserted into this composite data type.
         For example, suppose dt1 contains dt2. Therefore it is not valid
         to insert dt1 to dt2 since this would cause a cyclic dependency.
        @throws IndexOutOfBoundsException if component ordinal is out of bounds
        """
        ...

    @overload
    def insert(self, ordinal: int, dataType: ghidra.program.model.data.DataType, length: int) -> ghidra.program.model.data.DataTypeComponent:
        """
        Inserts a new datatype at the specified ordinal position in this composite.
         <BR>Note: For an aligned structure the ordinal position will get adjusted
         automatically to provide the proper alignment.
        @param ordinal the ordinal where the new datatype is to be inserted.
        @param dataType the datatype to insert.
        @param length the length to associate with the datatype.
         For fixed length types a length &lt;= 0 will use the length of the resolved dataType.
        @return the componentDataType created.
        @throws IllegalArgumentException if the specified data type is not
         allowed to be inserted into this composite data type or an invalid
         length is specified.
         For example, suppose dt1 contains dt2. Therefore it is not valid
         to insert dt1 to dt2 since this would cause a cyclic dependency.
        @throws IndexOutOfBoundsException if component ordinal is out of bounds
        """
        ...

    @overload
    def insert(self, ordinal: int, dataType: ghidra.program.model.data.DataType, length: int, name: unicode, comment: unicode) -> ghidra.program.model.data.DataTypeComponent:
        """
        Inserts a new datatype at the specified ordinal position in this composite.
         <BR>Note: For an aligned structure the ordinal position will get adjusted
         automatically to provide the proper alignment.
        @param ordinal the ordinal where the new datatype is to be inserted.
        @param dataType the datatype to insert.
        @param length the length to associate with the datatype.
         For fixed length types a length &lt;= 0 will use the length of the resolved dataType.
        @param name the field name to associate with this component.
        @param comment the comment to associate with this component.
        @return the componentDataType created.
        @throws IllegalArgumentException if the specified data type is not
         allowed to be inserted into this composite data type or an invalid length
         is specified.
         For example, suppose dt1 contains dt2. Therefore it is not valid
         to insert dt1 to dt2 since this would cause a cyclic dependency.
        @throws IndexOutOfBoundsException if component ordinal is out of bounds
        """
        ...

    def isDefaultAligned(self) -> bool:
        """
        Whether or not this data type is using the default alignment.  When Structure packing
         is disabled the default alignment is always 1 (see {@link Structure#setPackingEnabled(boolean)}.
        @return true if this data type is using its default alignment.
        """
        ...

    def isDeleted(self) -> bool: ...

    def isEncodable(self) -> bool: ...

    def isEquivalent(self, __a0: ghidra.program.model.data.DataType) -> bool: ...

    def isMachineAligned(self) -> bool:
        """
        Whether or not this data type is using the machine alignment value, specified by
         {@link DataOrganization#getMachineAlignment()}, for its alignment.
        @return true if this data type is using the machine alignment as its alignment.
        """
        ...

    def isNotYetDefined(self) -> bool: ...

    def isPackingEnabled(self) -> bool:
        """
        Determine if this data type has its internal components currently packed
         based upon alignment and packing settings.  If disabled, component placement
         is based upon explicit placement by offset.
        @return true if this data type's components auto-packed
        """
        ...

    def isPartOf(self, dataType: ghidra.program.model.data.DataType) -> bool:
        """
        Check if a data type is part of this data type.  A data type could
         be part of another by:
         <br>Being the same data type.
         <br>containing the data type directly
         <br>containing another data type that has the data type as a part of it.
        @param dataType the data type to look for.
        @return true if the indicated data type is part of a sub-component of
         this data type.
        """
        ...

    def isZeroLength(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def pack(self, packingValue: int) -> None:
        """
        Same as {@link #setExplicitPackingValue(int)}.
        @param packingValue the new positive packing value.
        @throws IllegalArgumentException if a non-positive value is specified.
        """
        ...

    def removeParent(self, __a0: ghidra.program.model.data.DataType) -> None: ...

    def repack(self) -> None:
        """
        Updates packed composite to any changes in the data organization. If the composite does
         not have packing enabled this method does nothing.
         <BR>
         NOTE: Changes to data organization is discouraged.  Attempts to use this method in such
         cases should be performed on all composites in dependency order (ignoring pointer components).
        """
        ...

    def replaceWith(self, __a0: ghidra.program.model.data.DataType) -> None: ...

    def setCategoryPath(self, __a0: ghidra.program.model.data.CategoryPath) -> None: ...

    def setDescription(self, desc: unicode) -> None:
        """
        Sets the string describing this data type.
        @param desc the new description.
        """
        ...

    def setExplicitMinimumAlignment(self, minAlignment: int) -> None:
        """
        Sets this data type's explicit minimum alignment (positive value).
         Together with the pack setting and component alignments will
         affect the actual computed alignment of this composite.
         When packing is enabled, the alignment setting may also affect padding
         at the end of the composite and its length.  When packing is disabled,
         this setting will not affect the length of this composite.
        @param minAlignment the minimum alignment for this Composite.
        @throws IllegalArgumentException if a non-positive value is specified
        """
        ...

    def setExplicitPackingValue(self, packingValue: int) -> None:
        """
        Sets the pack value for this composite (positive value, usually a power of 2).
         If packing was previously disabled, packing will be enabled.  This value will
         establish the maximum effective alignment for this composite and each of the
         components during the alignment computation (e.g., a value of 1 will eliminate
         any padding).  The overall composite length may be influenced by the composite's
         minimum alignment setting.
        @param packingValue the new positive packing value.
        @throws IllegalArgumentException if a non-positive value is specified.
        """
        ...

    def setLastChangeTime(self, __a0: long) -> None: ...

    def setLastChangeTimeInSourceArchive(self, __a0: long) -> None: ...

    def setName(self, __a0: unicode) -> None: ...

    def setNameAndCategory(self, __a0: ghidra.program.model.data.CategoryPath, __a1: unicode) -> None: ...

    def setPackingEnabled(self, enabled: bool) -> None:
        """
        Sets whether this data type's internal components are currently packed.  The
         affect of disabled packing differs between {@link Structure} and {@link Union}.  When
         packing disabled:
         <ul>
         <li>Structures utilize explicit component offsets and produce undefined filler
         components where defined components do not consume space.</li>
         <li>Unions always place components at offset 0 and do not pad for alignment.
         </ul>
         In addition, when packing is disabled the default alignment is always 1 unless a
         different minimum alignment has been set.  When packing is enabled the overall
         composite length influenced by the composite's minimum alignment setting.
         If a change in enablement occurs, the default alignment and packing behavior
         will be used.
        @param enabled true enables packing of components respecting component
         alignment and pack setting, whereas false disables packing.
        """
        ...

    def setSourceArchive(self, __a0: ghidra.program.model.data.SourceArchive) -> None: ...

    def setToDefaultAligned(self) -> None:
        """
        Sets this data type's alignment to its default alignment. For packed
         composites, this data type's alignment will be based upon the components it contains and
         its current pack settings.  This is the default state and only needs to be used
         when changing from a non-default alignment type.
        """
        ...

    def setToDefaultPacking(self) -> None:
        """
        Enables default packing behavior.
         If packing was previously disabled, packing will be enabled.
         Composite will automatically pack based upon the alignment requirements
         of its components with overall composite length possibly influenced by the composite's
         minimum alignment setting.
        """
        ...

    def setToMachineAligned(self) -> None:
        """
        Sets this data type's minimum alignment to the machine alignment which is
         specified by {@link DataOrganization#getMachineAlignment()}. The machine alignment is
         defined as the maximum useful alignment for the target machine.
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
    def alignmentType(self) -> ghidra.program.model.data.AlignmentType: ...

    @property
    def categoryPath(self) -> ghidra.program.model.data.CategoryPath: ...

    @categoryPath.setter
    def categoryPath(self, value: ghidra.program.model.data.CategoryPath) -> None: ...

    @property
    def components(self) -> List[ghidra.program.model.data.DataTypeComponent]: ...

    @property
    def dataOrganization(self) -> ghidra.program.model.data.DataOrganization: ...

    @property
    def dataTypeManager(self) -> ghidra.program.model.data.DataTypeManager: ...

    @property
    def dataTypePath(self) -> ghidra.program.model.data.DataTypePath: ...

    @property
    def defaultAbbreviatedLabelPrefix(self) -> unicode: ...

    @property
    def defaultAligned(self) -> bool: ...

    @property
    def defaultLabelPrefix(self) -> unicode: ...

    @property
    def defaultSettings(self) -> ghidra.docking.settings.Settings: ...

    @property
    def definedComponents(self) -> List[ghidra.program.model.data.DataTypeComponent]: ...

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
    def explicitMinimumAlignment(self) -> int: ...

    @explicitMinimumAlignment.setter
    def explicitMinimumAlignment(self, value: int) -> None: ...

    @property
    def explicitPackingValue(self) -> int: ...

    @explicitPackingValue.setter
    def explicitPackingValue(self, value: int) -> None: ...

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
    def machineAligned(self) -> bool: ...

    @property
    def name(self) -> unicode: ...

    @name.setter
    def name(self, value: unicode) -> None: ...

    @property
    def notYetDefined(self) -> bool: ...

    @property
    def numComponents(self) -> int: ...

    @property
    def numDefinedComponents(self) -> int: ...

    @property
    def packingEnabled(self) -> bool: ...

    @packingEnabled.setter
    def packingEnabled(self, value: bool) -> None: ...

    @property
    def packingType(self) -> ghidra.program.model.data.PackingType: ...

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