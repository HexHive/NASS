from typing import List
import ghidra.docking.settings
import ghidra.program.model.data
import ghidra.program.model.mem
import ghidra.util
import java.lang
import java.net
import java.util
import java.util.function


class Structure(ghidra.program.model.data.Composite, object):
    """
    The structure interface.
 
     NOTE: A zero-length Structure will report a length of 1 which will result in
     improper code unit sizing since we are unable to support a defined data of length 0.
 
     NOTE: The use of zero-length bitfields within non-packed structures is discouraged since they have
     no real affect and are easily misplaced. Their use should be reserved for packed
     structures.
    """

    CONFLICT_SUFFIX: unicode = u'.conflict'
    DEFAULT: ghidra.program.model.data.DataType = undefined
    NO_LAST_CHANGE_TIME: long = 0x0L
    NO_SOURCE_SYNC_TIME: long = 0x0L
    TYPEDEF_ATTRIBUTE_PREFIX: unicode = u'__(('
    TYPEDEF_ATTRIBUTE_SUFFIX: unicode = u'))'
    VOID: ghidra.program.model.data.DataType = void




    class BitOffsetComparator(object, java.util.Comparator):
        INSTANCE_BE: java.util.Comparator = ghidra.program.model.data.Structure$BitOffsetComparator@f37ee18
        INSTANCE_LE: java.util.Comparator = ghidra.program.model.data.Structure$BitOffsetComparator@44f82240



        def __init__(self, __a0: bool): ...



        def compare(self, __a0: object, __a1: object) -> int: ...

        @overload
        @staticmethod
        def comparing(__a0: java.util.function.Function) -> java.util.Comparator: ...

        @overload
        @staticmethod
        def comparing(__a0: java.util.function.Function, __a1: java.util.Comparator) -> java.util.Comparator: ...

        @staticmethod
        def comparingDouble(__a0: java.util.function.ToDoubleFunction) -> java.util.Comparator: ...

        @staticmethod
        def comparingInt(__a0: java.util.function.ToIntFunction) -> java.util.Comparator: ...

        @staticmethod
        def comparingLong(__a0: java.util.function.ToLongFunction) -> java.util.Comparator: ...

        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        @staticmethod
        def getNormalizedBitfieldOffset(__a0: int, __a1: int, __a2: int, __a3: int, __a4: bool) -> int: ...

        def hashCode(self) -> int: ...

        @staticmethod
        def naturalOrder() -> java.util.Comparator: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        @staticmethod
        def nullsFirst(__a0: java.util.Comparator) -> java.util.Comparator: ...

        @staticmethod
        def nullsLast(__a0: java.util.Comparator) -> java.util.Comparator: ...

        @staticmethod
        def reverseOrder() -> java.util.Comparator: ...

        def reversed(self) -> java.util.Comparator: ...

        @overload
        def thenComparing(self, __a0: java.util.Comparator) -> java.util.Comparator: ...

        @overload
        def thenComparing(self, __a0: java.util.function.Function) -> java.util.Comparator: ...

        @overload
        def thenComparing(self, __a0: java.util.function.Function, __a1: java.util.Comparator) -> java.util.Comparator: ...

        def thenComparingDouble(self, __a0: java.util.function.ToDoubleFunction) -> java.util.Comparator: ...

        def thenComparingInt(self, __a0: java.util.function.ToIntFunction) -> java.util.Comparator: ...

        def thenComparingLong(self, __a0: java.util.function.ToLongFunction) -> java.util.Comparator: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...







    @overload
    def add(self, __a0: ghidra.program.model.data.DataType) -> ghidra.program.model.data.DataTypeComponent: ...

    @overload
    def add(self, __a0: ghidra.program.model.data.DataType, __a1: int) -> ghidra.program.model.data.DataTypeComponent: ...

    @overload
    def add(self, __a0: ghidra.program.model.data.DataType, __a1: unicode, __a2: unicode) -> ghidra.program.model.data.DataTypeComponent: ...

    @overload
    def add(self, __a0: ghidra.program.model.data.DataType, __a1: int, __a2: unicode, __a3: unicode) -> ghidra.program.model.data.DataTypeComponent: ...

    def addBitField(self, __a0: ghidra.program.model.data.DataType, __a1: int, __a2: unicode, __a3: unicode) -> ghidra.program.model.data.DataTypeComponent: ...

    def addParent(self, __a0: ghidra.program.model.data.DataType) -> None: ...

    def align(self, __a0: int) -> None: ...

    def clearAtOffset(self, offset: int) -> None:
        """
        Clears all defined components containing the specified offset in this structure. If the offset
         corresponds to a bit-field or zero-length component (e.g., 0-element array) multiple 
         components may be cleared.  This method will preserve the structure length and placement 
         of other components since freed space will appear as undefined components.
         <p>
         To avoid clearing zero-length components at a specified offset within a non-packed structure,
         the {@link #replaceAtOffset(int, DataType, int, String, String)} may be used with to clear
         only the sized component at the offset by specified {@link DataType#DEFAULT} as the replacement
         datatype.
        @param offset the byte offset into the structure where the component(s) are to be deleted.
        """
        ...

    def clearComponent(self, ordinal: int) -> None:
        """
        Clears the defined component at the specified component ordinal. Clearing a component within
         a non-packed structure causes a defined component to be replaced with a number of undefined 
         components.  This may not the case when clearing a zero-length component or bit-field 
         which may not result in such undefined components.  In the case of a packed structure 
         clearing is always completed without backfill.
        @param ordinal the ordinal of the component to clear.
        @throws IndexOutOfBoundsException if component ordinal is out of bounds
        """
        ...

    def clone(self, dtm: ghidra.program.model.data.DataTypeManager) -> ghidra.program.model.data.Structure: ...

    def copy(self, __a0: ghidra.program.model.data.DataTypeManager) -> ghidra.program.model.data.DataType: ...

    def dataTypeAlignmentChanged(self, __a0: ghidra.program.model.data.DataType) -> None: ...

    def dataTypeDeleted(self, __a0: ghidra.program.model.data.DataType) -> None: ...

    def dataTypeNameChanged(self, __a0: ghidra.program.model.data.DataType, __a1: unicode) -> None: ...

    def dataTypeReplaced(self, __a0: ghidra.program.model.data.DataType, __a1: ghidra.program.model.data.DataType) -> None: ...

    def dataTypeSizeChanged(self, __a0: ghidra.program.model.data.DataType) -> None: ...

    @overload
    def delete(self, __a0: int) -> None: ...

    @overload
    def delete(self, __a0: java.util.Set) -> None: ...

    def deleteAll(self) -> None:
        """
        Remove all components from this structure, effectively setting the
         length to zero.  Packing and minimum alignment settings are unaffected.
        """
        ...

    def deleteAtOffset(self, offset: int) -> None:
        """
        Deletes all defined components containing the specified offset in this structure. If the offset
         corresponds to a bit-field or zero-length component (e.g., 0-element array) multiple 
         components may be deleted.  Bit-fields are only cleared and may leave residual undefined 
         components in their place.  This method will generally reduce the length of the structure.
         The {@link #clearAtOffset(int)} method should be used for non-packed structures to 
         preserve the structure length and placement of other components.
        @param offset the byte offset into the structure where the component(s) are to be deleted.
         An offset equal to the structure length may be specified to delete any trailing zero-length 
         components.
        @throws IllegalArgumentException if a negative offset is specified
        """
        ...

    def dependsOn(self, __a0: ghidra.program.model.data.DataType) -> bool: ...

    def encodeRepresentation(self, __a0: unicode, __a1: ghidra.program.model.mem.MemBuffer, __a2: ghidra.docking.settings.Settings, __a3: int) -> List[int]: ...

    def encodeValue(self, __a0: object, __a1: ghidra.program.model.mem.MemBuffer, __a2: ghidra.docking.settings.Settings, __a3: int) -> List[int]: ...

    def equals(self, __a0: object) -> bool: ...

    def getAlignedLength(self) -> int: ...

    def getAlignment(self) -> int: ...

    def getAlignmentType(self) -> ghidra.program.model.data.AlignmentType: ...

    def getCategoryPath(self) -> ghidra.program.model.data.CategoryPath: ...

    def getClass(self) -> java.lang.Class: ...

    def getComponent(self, ordinal: int) -> ghidra.program.model.data.DataTypeComponent:
        """
        Returns the component of this structure with the indicated ordinal.
        @param ordinal the ordinal of the component requested.
        @return the data type component.
        @throws IndexOutOfBoundsException if the ordinal is out of bounds
        """
        ...

    def getComponentAt(self, offset: int) -> ghidra.program.model.data.DataTypeComponent:
        """
        Gets the first non-zero-length component that starts at the specified offset. 
         Note that one or more components may share the same offset when a bit-field or zero-length
         component is present since these may share an offset.  A null may be returned under one of
         the following conditions:
         <ul>
         <li>offset only corresponds to a zero-length component within a packed structure</li>
         <li>offset corresponds to a padding byte within a packed structure</li>
         <li>offset is contained within a component but is not the starting offset of that component</li>
         <li>offset is &gt;= structure length</li>
         </ul>
         If a bitfield is returned, and the caller supports bitfields, it is recommended that 
         {@link #getComponentsContaining(int)} be invoked to gather all bitfields which contain the 
         specified offset.
        @param offset the byte offset into this structure
        @return the first component that starts at specified offset or null if not found.
        """
        ...

    def getComponentContaining(self, offset: int) -> ghidra.program.model.data.DataTypeComponent:
        """
        Gets the first non-zero-length component that contains the byte at the specified offset. 
         Note that one or more components may share the same offset when a bit-field or zero-length
         component is present since these may share an offset.  A null may be returned under one of
         the following conditions:
         <ul>
         <li>offset only corresponds to a zero-length component within a packed structure</li>
         <li>offset corresponds to a padding byte within a packed structure</li>
         <li>offset is &gt;= structure length.</li>
         </ul>
         If a bitfield is returned, and the caller supports bitfields, it is recommended that 
         {@link #getComponentsContaining(int)} be invoked to gather all bitfields which contain the 
         specified offset.
        @param offset the byte offset into this structure
        @return the first non-zero-length component that contains the byte at the specified offset
         or null if not found.
        """
        ...

    def getComponents(self) -> List[ghidra.program.model.data.DataTypeComponent]: ...

    def getComponentsContaining(self, offset: int) -> List[ghidra.program.model.data.DataTypeComponent]:
        """
        Get an ordered list of components that contain the byte at the specified offset.
         Unlike {@link #getComponentAt(int)} and {@link #getComponentContaining(int)} this method will
         include zero-length components if they exist at the specified offset.  For this reason the
         specified offset may equal the structure length to obtain and trailing zero-length components.
         Note that this method will only return more than one component when a bit-fields and/or 
         zero-length components are present since these may share an offset. An empty list may be 
         returned under the following conditions:
         <ul>
         <li>offset only corresponds to a padding byte within a packed structure</li>
         <li>offset is equal structure length and no trailing zero-length components exist</li>
         <li>offset is &gt; structure length</li>
         </ul>
        @param offset the byte offset into this structure
        @return a list of zero or more components containing the specified offset
        """
        ...

    def getDataOrganization(self) -> ghidra.program.model.data.DataOrganization: ...

    def getDataTypeAt(self, offset: int) -> ghidra.program.model.data.DataTypeComponent:
        """
        Returns the lowest-level component that contains the specified offset. This is useful 
         for structures that have sub-structures. This method is best used when working with 
         known structures which do not contain bitfields or zero-length components since in 
         those situations multiple components may correspond to the specified offset.  
         A similar ambiguous condition occurs if offset corresponds to a union component.
        @param offset the byte offset into this data type.
        @return a primitive component data type which contains the specified offset.
        """
        ...

    def getDataTypeManager(self) -> ghidra.program.model.data.DataTypeManager: ...

    def getDataTypePath(self) -> ghidra.program.model.data.DataTypePath: ...

    def getDefaultAbbreviatedLabelPrefix(self) -> unicode: ...

    @overload
    def getDefaultLabelPrefix(self) -> unicode: ...

    @overload
    def getDefaultLabelPrefix(self, __a0: ghidra.program.model.mem.MemBuffer, __a1: ghidra.docking.settings.Settings, __a2: int, __a3: ghidra.program.model.data.DataTypeDisplayOptions) -> unicode: ...

    def getDefaultOffcutLabelPrefix(self, __a0: ghidra.program.model.mem.MemBuffer, __a1: ghidra.docking.settings.Settings, __a2: int, __a3: ghidra.program.model.data.DataTypeDisplayOptions, __a4: int) -> unicode: ...

    def getDefaultSettings(self) -> ghidra.docking.settings.Settings: ...

    def getDefinedComponentAtOrAfterOffset(self, offset: int) -> ghidra.program.model.data.DataTypeComponent:
        """
        Gets the first defined component located at or after the specified offset. 
         Note: The returned component may be a zero-length component.
        @param offset the byte offset into this structure
        @return the first defined component located at or after the specified offset or null if not found.
        """
        ...

    def getDefinedComponents(self) -> List[ghidra.program.model.data.DataTypeComponent]: ...

    def getDescription(self) -> unicode: ...

    def getDisplayName(self) -> unicode: ...

    def getDocs(self) -> java.net.URL: ...

    def getExplicitMinimumAlignment(self) -> int: ...

    def getExplicitPackingValue(self) -> int: ...

    def getLastChangeTime(self) -> long: ...

    def getLastChangeTimeInSourceArchive(self) -> long: ...

    def getLength(self) -> int: ...

    def getMnemonic(self, __a0: ghidra.docking.settings.Settings) -> unicode: ...

    def getName(self) -> unicode: ...

    def getNumComponents(self) -> int: ...

    def getNumDefinedComponents(self) -> int: ...

    def getPackingType(self) -> ghidra.program.model.data.PackingType: ...

    def getParents(self) -> java.util.Collection: ...

    def getPathName(self) -> unicode: ...

    def getRepresentation(self, __a0: ghidra.program.model.mem.MemBuffer, __a1: ghidra.docking.settings.Settings, __a2: int) -> unicode: ...

    def getSettingsDefinitions(self) -> List[ghidra.docking.settings.SettingsDefinition]: ...

    def getSourceArchive(self) -> ghidra.program.model.data.SourceArchive: ...

    def getTypeDefSettingsDefinitions(self) -> List[ghidra.program.model.data.TypeDefSettingsDefinition]: ...

    def getUniversalID(self) -> ghidra.util.UniversalID: ...

    def getValue(self, __a0: ghidra.program.model.mem.MemBuffer, __a1: ghidra.docking.settings.Settings, __a2: int) -> object: ...

    def getValueClass(self, __a0: ghidra.docking.settings.Settings) -> java.lang.Class: ...

    def growStructure(self, amount: int) -> None:
        """
        Increases the size of the structure by the specified amount by adding undefined filler at the
         end of the structure.  NOTE: This method only has an affect on non-packed structures.
        @param amount the amount by which to grow the structure.
        @throws IllegalArgumentException if amount &lt; 1
        """
        ...

    def hasDefaultPacking(self) -> bool: ...

    def hasExplicitMinimumAlignment(self) -> bool: ...

    def hasExplicitPackingValue(self) -> bool: ...

    def hasLanguageDependantLength(self) -> bool: ...

    def hashCode(self) -> int: ...

    @overload
    def insert(self, __a0: int, __a1: ghidra.program.model.data.DataType) -> ghidra.program.model.data.DataTypeComponent: ...

    @overload
    def insert(self, __a0: int, __a1: ghidra.program.model.data.DataType, __a2: int) -> ghidra.program.model.data.DataTypeComponent: ...

    @overload
    def insert(self, __a0: int, __a1: ghidra.program.model.data.DataType, __a2: int, __a3: unicode, __a4: unicode) -> ghidra.program.model.data.DataTypeComponent: ...

    @overload
    def insertAtOffset(self, offset: int, dataType: ghidra.program.model.data.DataType, length: int) -> ghidra.program.model.data.DataTypeComponent:
        """
        Inserts a new datatype at the specified offset into this structure. Inserting a component
         will cause any conflicting components to shift down to the extent necessary to avoid a
         conflict.
        @param offset the byte offset into the structure where the new datatype is to be inserted.
        @param dataType the datatype to insert.  If {@link DataType#DEFAULT} is specified for a packed 
         				structure an {@link Undefined1DataType} will be used in its place.
        @param length the length to associate with the dataType. For fixed length types a length
                    &lt;= 0 will use the length of the resolved dataType.
        @return the componentDataType created.
        @throws IllegalArgumentException if the specified data type is not allowed to be inserted
                     into this composite data type or an invalid length is specified. For example,
                     suppose dt1 contains dt2. Therefore it is not valid to insert dt1 to dt2 since
                     this would cause a cyclic dependency.
        """
        ...

    @overload
    def insertAtOffset(self, offset: int, dataType: ghidra.program.model.data.DataType, length: int, name: unicode, comment: unicode) -> ghidra.program.model.data.DataTypeComponent:
        """
        Inserts a new datatype at the specified offset into this structure. Inserting a component
         will cause any conflicting components to shift down to the extent necessary to avoid a
         conflict.
         <p>
         This method does not support bit-field insertions which must use the method 
         {@link #insertBitFieldAt(int, int, int, DataType, int, String, String)}.
        @param offset the byte offset into the structure where the new datatype is to be inserted.
        @param dataType the datatype to insert.  If {@link DataType#DEFAULT} is specified for a packed 
         				structure an {@link Undefined1DataType} will be used in its place.
        @param length the length to associate with the dataType. For fixed length types a length
                    &lt;= 0 will use the length of the resolved dataType.
        @param name the field name to associate with this component.
        @param comment the comment to associate with this component.
        @return the componentDataType created.
        @throws IllegalArgumentException if the specified data type is not allowed to be inserted
                     into this composite data type or an invalid length is specified. For example,
                     suppose dt1 contains dt2. Therefore it is not valid to insert dt1 to dt2 since
                     this would cause a cyclic dependency.
        """
        ...

    def insertBitField(self, ordinal: int, byteWidth: int, bitOffset: int, baseDataType: ghidra.program.model.data.DataType, bitSize: int, componentName: unicode, comment: unicode) -> ghidra.program.model.data.DataTypeComponent:
        """
        Inserts a new bitfield at the specified ordinal position in this structure. Within packed
         structures the specified byteWidth and bitOffset will be ignored since packing will occur at
         the specified ordinal position. The resulting component length and bitfield details will
         reflect the use of minimal storage sizing.
         <p>
         For structures with packing disabled, a component shift will only occur if the bitfield placement
         conflicts with another component. If no conflict occurs, the bitfield will be placed at the
         specified location consuming any DEFAULT components as needed. When a conflict does occur a
         shift will be performed at the ordinal position based upon the specified byteWidth. When
         located onto existing bitfields they will be packed together provided they do not conflict,
         otherwise the conflict rule above applies.
         <p>
         Supported packing starts with bit-0 (lsb) of the first byte for little-endian, and
         with bit-7 (msb) of the first byte for big-endian. This is the default behavior for most
         compilers. Insertion behavior may not work as expected if packing rules differ from this.
        @param ordinal the ordinal of the component to be inserted.
        @param byteWidth the storage allocation unit width which contains the bitfield. Must be large
                    enough to contain the "effective bit size" and corresponding bitOffset. The actual
                    component size used will be recomputed during insertion.
        @param bitOffset corresponds to the bitfield left-shift amount with the storage unit when
                    viewed as big-endian. The final offset may be reduced based upon the minimal
                    storage size determined during insertion.
        @param baseDataType the bitfield base datatype (certain restrictions apply).
        @param bitSize the declared bitfield size in bits. The effective bit size may be adjusted
                    based upon the specified baseDataType.
        @param componentName the field name to associate with this component.
        @param comment the comment to associate with this component.
        @return the bitfield component created whose associated data type will be BitFieldDataType.
        @throws InvalidDataTypeException if the specified baseDataType is not a valid base type for
                     bitfields.
        @throws IndexOutOfBoundsException if ordinal is less than 0 or greater than the current
                     number of components.
        """
        ...

    def insertBitFieldAt(self, byteOffset: int, byteWidth: int, bitOffset: int, baseDataType: ghidra.program.model.data.DataType, bitSize: int, componentName: unicode, comment: unicode) -> ghidra.program.model.data.DataTypeComponent:
        """
        Inserts a new bitfield at the specified location in this composite. This method is intended
         to be used with structures with packing disabled where the bitfield will be precisely placed. Within an
         packed structure the specified byteOffset, byteWidth and bitOffset will be used to identify
         the appropriate ordinal but may not be preserved. The component length will be computed based
         upon the specified parameters and will be reduced from byteWidth to its minimal size for the
         new component.
         <p>
         When packing disabled, a component shift will only occur if the bitfield placement conflicts
         with another component. If no conflict occurs, the bitfield will be placed at the specified
         location consuming any DEFAULT components as needed. When a conflict does occur a shift will
         be performed at the point of conflict based upon the specified byteWidth. When located onto
         existing bitfields they will be packed together provided they do not conflict, otherwise the
         conflict rule above applies.
         <p>
         Supported packing for little-endian fills lsb first, whereas big-endian fills msb first.
         Insertion behavior may not work as expected if packing rules differ from this.
         <p>
 
         Zero length bitfields may be inserted although they have no real affect when packing disabled. 
         Only the resulting byte offset within the structure is of significance in
         determining its ordinal placement.
         <p>
        @param byteOffset the first byte offset within this structure which corresponds to the first
                    byte of the specified storage unit identified by its byteWidth.
        @param byteWidth the storage unit width which contains the bitfield. Must be large enough to
                    contain the specified bitSize and corresponding bitOffset. The actual component
                    size used will be recomputed during insertion.
        @param bitOffset corresponds to the bitfield left-shift amount with the storage unit when
                    viewed as big-endian. The final offset may be reduced based upon the minimal
                    storage size determined during insertion.
        @param baseDataType the bitfield base datatype (certain restrictions apply).
        @param componentName the field name to associate with this component.
        @param bitSize the bitfield size in bits. A bitSize of 0 may be specified although its name
                    will be ignored.
        @param comment the comment to associate with this component.
        @return the componentDataType created whose associated data type will be BitFieldDataType.
        @throws InvalidDataTypeException if the specified data type is not a valid base type for
                     bitfields.
        """
        ...

    def isDefaultAligned(self) -> bool: ...

    def isDeleted(self) -> bool: ...

    def isEncodable(self) -> bool: ...

    def isEquivalent(self, __a0: ghidra.program.model.data.DataType) -> bool: ...

    def isMachineAligned(self) -> bool: ...

    def isNotYetDefined(self) -> bool: ...

    def isPackingEnabled(self) -> bool: ...

    def isPartOf(self, __a0: ghidra.program.model.data.DataType) -> bool: ...

    def isZeroLength(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def pack(self, __a0: int) -> None: ...

    def removeParent(self, __a0: ghidra.program.model.data.DataType) -> None: ...

    def repack(self) -> None: ...

    @overload
    def replace(self, ordinal: int, dataType: ghidra.program.model.data.DataType, length: int) -> ghidra.program.model.data.DataTypeComponent:
        """
        Replaces the component at the specified ordinal with a new component using the 
         specified datatype, length, name and comment.  In the case of a packed structure 
         a 1-for-1 replacement will occur.  In the case of a non-packed structure certain
         restrictions apply:
         <ul>
         <li>A zero-length component may only be replaced with another zero-length component.</li>
         <li>If ordinal corresponds to a bit-field, all bit-fields which overlap the specified 
         bit-field will be replaced.</li>
         </ul>
         There must be sufficient space to complete the replacement factoring in the space freed 
         by the consumed component(s).  If there are no remaining defined components beyond the 
         consumed components the structure will expand its length as needed. For a packed structure, this 
         method behaves the same as a ordinal-based delete followed by an insert.
         <p>
         Datatypes not permitted include {@link FactoryDataType} types, non-sizable 
         {@link Dynamic} types, and those which result in a circular direct dependency.
         <p>
         NOTE: In general, it is not recommended that this method be used with non-packed 
         structures where the replaced component is a bit-field.
        @param ordinal the ordinal of the component to be replaced.
        @param dataType the datatype to insert. If {@link DataType#DEFAULT} is specified for a packed 
                     structure an {@link Undefined1DataType} will be used in its place.  If {@link DataType#DEFAULT} 
                     is specified for a non-packed structure this is equivelant to {@link #clearComponent(int)}, ignoring
                     the length, name and comment arguments.
        @param length component length for containing the specified dataType. A positive length is required 
                     for sizable {@link Dynamic} datatypes and should be specified as -1 for fixed-length
                     datatypes to rely on their resolved size.
        @return the new component.
        @throws IllegalArgumentException may be caused by: 1) invalid offset specified, 2) invalid datatype or 
                     associated length specified, or 3) insufficient space for replacement.
        @throws IndexOutOfBoundsException if component ordinal is out of bounds
        """
        ...

    @overload
    def replace(self, ordinal: int, dataType: ghidra.program.model.data.DataType, length: int, name: unicode, comment: unicode) -> ghidra.program.model.data.DataTypeComponent:
        """
        Replaces the component at the specified ordinal with a new component using the 
         specified datatype, length, name and comment.  In the case of a packed structure 
         a 1-for-1 replacement will occur.  In the case of a non-packed structure certain
         restrictions apply:
         <ul>
         <li>A zero-length component may only be replaced with another zero-length component.</li>
         <li>If ordinal corresponds to a bit-field, all bit-fields which overlap the specified 
         bit-field will be replaced.</li>
         </ul>
         There must be sufficient space to complete the replacement factoring in the space freed 
         by the consumed component(s).  If there are no remaining defined components beyond the 
         consumed components the structure will expand its length as needed. For a packed structure, this 
         method behaves the same as a ordinal-based delete followed by an insert.
         <p>
         Datatypes not permitted include {@link FactoryDataType} types, non-sizable 
         {@link Dynamic} types, and those which result in a circular direct dependency.
         <p>
         NOTE: In general, it is not recommended that this method be used with non-packed 
         structures where the replaced component is a bit-field.
        @param ordinal the ordinal of the component to be replaced.
        @param dataType the datatype to insert.  If {@link DataType#DEFAULT} is specified for a packed 
                     structure an {@link Undefined1DataType} will be used in its place.  If {@link DataType#DEFAULT} 
                     is specified for a non-packed structure this is equivelant to {@link #clearComponent(int)}, ignoring
                     the length, name and comment arguments.
        @param length component length for containing the specified dataType. A positive length is required 
                     for sizable {@link Dynamic} datatypes and should be specified as -1 for fixed-length
                     datatypes to rely on their resolved size.
        @param name the field name to associate with this component or null.
        @param comment the comment to associate with this component or null.
        @return the new component.
        @throws IllegalArgumentException may be caused by: 1) invalid offset specified, 2) invalid datatype or 
                     associated length specified, or 3) insufficient space for replacement.
        @throws IndexOutOfBoundsException if component ordinal is out of bounds
        """
        ...

    def replaceAtOffset(self, offset: int, dataType: ghidra.program.model.data.DataType, length: int, name: unicode, comment: unicode) -> ghidra.program.model.data.DataTypeComponent:
        """
        Replaces all components containing the specified byte offset with a new component using the 
         specified datatype, length, name and comment. If the offset corresponds to a bit-field 
         more than one component may be consumed by this replacement.  
         <p>
         This method may not be used to replace a zero-length component since there may be any number 
         of zero-length components at the same offset. If the only defined component(s) at the specified
         offset are zero-length the subsequent undefined will be replaced in the case of a non-packed 
         structure.  For a packed structure such a case would be treated as an insert as would an offset 
         which is not contained within a component.  
         <p>
         For a non-packed structure a replacement will attempt to consume sufficient
         space within moving other defined components.  There must be sufficient space to complete 
         the replacement factoring in the space freed by the consumed component(s).  When replacing the 
         last defined component the structure size will be expanded as needed to fit the new component.
         For a packed If there are no remaining defined components beyond 
         the consumed components, or an offset equals to the structure length is specified, the
         structure will expand its length as needed. 
         <p>
         For a non-packed structure the new component will use the specified offset.  In the case of 
         packed structure, the actual offset will be determined during a repack.
         <p>
         Datatypes not permitted include {@link FactoryDataType} types, non-sizable 
         {@link Dynamic} types, and those which result in a circular direct dependency.
        @param offset the byte offset into the structure where the datatype is to be placed.  The specified
                     offset must be less than the length of the structure.
        @param dataType the datatype to insert.  If {@link DataType#DEFAULT} is specified for a packed 
         			   structure an {@link Undefined1DataType} will be used in its place.  If {@link DataType#DEFAULT} 
                     is specified for a non-packed structure this is equivelant to clearing all components, 
                     which contain the specified offset, ignoring the length, name and comment arguments.
        @param length component length for containing the specified dataType. A positive length is required 
                     for sizable {@link Dynamic} datatypes and should be specified as -1 for fixed-length
                     datatypes to rely on their resolved size.
        @param name the field name to associate with this component or null.
        @param comment the comment to associate with this component or null.
        @return the new component.
        @throws IllegalArgumentException may be caused by: 1) invalid offset specified, 2) invalid datatype or 
                     associated length specified, or 3) insufficient space for replacement.
        """
        ...

    def replaceWith(self, __a0: ghidra.program.model.data.DataType) -> None: ...

    def setCategoryPath(self, __a0: ghidra.program.model.data.CategoryPath) -> None: ...

    def setDescription(self, __a0: unicode) -> None: ...

    def setExplicitMinimumAlignment(self, __a0: int) -> None: ...

    def setExplicitPackingValue(self, __a0: int) -> None: ...

    def setLastChangeTime(self, __a0: long) -> None: ...

    def setLastChangeTimeInSourceArchive(self, __a0: long) -> None: ...

    def setName(self, __a0: unicode) -> None: ...

    def setNameAndCategory(self, __a0: ghidra.program.model.data.CategoryPath, __a1: unicode) -> None: ...

    def setPackingEnabled(self, __a0: bool) -> None: ...

    def setSourceArchive(self, __a0: ghidra.program.model.data.SourceArchive) -> None: ...

    def setToDefaultAligned(self) -> None: ...

    def setToDefaultPacking(self) -> None: ...

    def setToMachineAligned(self) -> None: ...

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