import ghidra.docking.settings
import ghidra.program.model.data
import java.lang


class DataTypeComponent(object):
    """
    DataTypeComponents are holders for the dataTypes that make up composite (Structures
     and Unions) dataTypes.
    """

    DEFAULT_FIELD_NAME_PREFIX: unicode = u'field'







    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getComment(self) -> unicode:
        """
        Get the comment for this dataTypeComponent.
        @return component comment string or null if one has not been set
        """
        ...

    def getDataType(self) -> ghidra.program.model.data.DataType:
        """
        Returns the dataType in this component.
        @return the dataType in this component
        """
        ...

    def getDefaultFieldName(self) -> unicode:
        """
        Returns a default field name for this component.  Used only if a field name is not set.
        @return default field name (may be null for nameless fields such as a zero-length bitfield).
        """
        ...

    def getDefaultSettings(self) -> ghidra.docking.settings.Settings:
        """
        Gets the default settings for this data type component.
        @return a Settings object that is the set of default values for this dataType component
        """
        ...

    def getEndOffset(self) -> int:
        """
        Get the byte offset of where this component ends relative to the start of the parent
         data type.
        @return offset of end of component relative to the start of the parent
         data type.
        """
        ...

    def getFieldName(self) -> unicode:
        """
        Get this component's field name within its parent.
         If this method returns null {@link #getDefaultFieldName()} can be used to obtain a default
         generated field name.
        @return this component's field name within its parent or null if one has not been set.
        """
        ...

    def getLength(self) -> int:
        """
        Get the length of this component.  Zero-length components will report a length of 0
         and may overlap other components at the same offset.  Similarly, multiple adjacent
         bit-field components may appear to overlap at the byte-level.
        @return the length of this component
        """
        ...

    def getOffset(self) -> int:
        """
        Get the byte offset of where this component begins relative to the start of the parent
         data type.
        @return offset of start of component relative to the start of the parent
         data type.
        """
        ...

    def getOrdinal(self) -> int:
        """
        Get the ordinal position within the parent dataType.
        @return ordinal of this component within the parent data type.
        """
        ...

    def getParent(self) -> ghidra.program.model.data.DataType:
        """
        returns the dataType that contains this component.
        @return the dataType that contains this component.
        """
        ...

    def hashCode(self) -> int: ...

    def isBitFieldComponent(self) -> bool:
        """
        Determine if the specified component corresponds to a bit-field.
        @return true if bit-field else false
        """
        ...

    def isEquivalent(self, dtc: ghidra.program.model.data.DataTypeComponent) -> bool:
        """
        Returns true if the given dataTypeComponent is equivalent to this dataTypeComponent.
         A dataTypeComponent is "equivalent" if the other component has a data type
         that is equivalent to this component's data type. The dataTypeComponents must
         also have the same offset, field name, and comment.  The length is only checked
         for components which are dynamic and whose size must be specified when creating
         a component.
        @param dtc the dataTypeComponent being tested for equivalence.
        @return true if the given dataTypeComponent is equivalent to this dataTypeComponent.
        """
        ...

    def isZeroBitFieldComponent(self) -> bool:
        """
        Determine if the specified component corresponds to a zero-length bit-field.
        @return true if zero-length bit-field else false
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setComment(self, comment: unicode) -> None:
        """
        Sets the comment for the component.
        @param comment this components comment or null to clear comment.
        """
        ...

    def setFieldName(self, fieldName: unicode) -> None:
        """
        Sets the field name. If the field name is empty it will be set to null,
         which is the default field name. An exception is thrown if one of the
         parent's other components already has the specified field name.
        @param fieldName the new field name for this component.
        @throws DuplicateNameException if another component of the parent has
         the specified field name.
        """
        ...

    def toString(self) -> unicode: ...

    @staticmethod
    def usesZeroLengthComponent(dataType: ghidra.program.model.data.DataType) -> bool:
        """
        Determine if the specified dataType will be treated as a zero-length component
         allowing it to possibly overlap the next component.  If the specified dataType
         returns true for {@link DataType#isZeroLength()} and true for {@link DataType#isNotYetDefined()}
         this method will return false causing the associated component to use the reported dataType length
         of 1.
        @param dataType datatype to be evaluated
        @return true if zero-length component
        """
        ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def bitFieldComponent(self) -> bool: ...

    @property
    def comment(self) -> unicode: ...

    @comment.setter
    def comment(self, value: unicode) -> None: ...

    @property
    def dataType(self) -> ghidra.program.model.data.DataType: ...

    @property
    def defaultFieldName(self) -> unicode: ...

    @property
    def defaultSettings(self) -> ghidra.docking.settings.Settings: ...

    @property
    def endOffset(self) -> int: ...

    @property
    def fieldName(self) -> unicode: ...

    @fieldName.setter
    def fieldName(self, value: unicode) -> None: ...

    @property
    def length(self) -> int: ...

    @property
    def offset(self) -> int: ...

    @property
    def ordinal(self) -> int: ...

    @property
    def parent(self) -> ghidra.program.model.data.DataType: ...

    @property
    def zeroBitFieldComponent(self) -> bool: ...