import ghidra.docking.settings
import ghidra.program.model.data
import java.lang


class InternalDataTypeComponent(ghidra.program.model.data.DataTypeComponent, object):
    DEFAULT_FIELD_NAME_PREFIX: unicode = u'field'







    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getComment(self) -> unicode: ...

    def getDataType(self) -> ghidra.program.model.data.DataType: ...

    def getDefaultFieldName(self) -> unicode: ...

    def getDefaultSettings(self) -> ghidra.docking.settings.Settings: ...

    def getEndOffset(self) -> int: ...

    def getFieldName(self) -> unicode: ...

    def getLength(self) -> int: ...

    def getOffset(self) -> int: ...

    def getOrdinal(self) -> int: ...

    def getParent(self) -> ghidra.program.model.data.DataType: ...

    def hashCode(self) -> int: ...

    def isBitFieldComponent(self) -> bool: ...

    def isEquivalent(self, __a0: ghidra.program.model.data.DataTypeComponent) -> bool: ...

    def isZeroBitFieldComponent(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setComment(self, __a0: unicode) -> None: ...

    def setDataType(self, dataType: ghidra.program.model.data.DataType) -> None:
        """
        Sets the DataType for this component.  Must be used carefully since the component
         will not be resized.
        @param dataType the new DataType for this component
        """
        ...

    def setFieldName(self, __a0: unicode) -> None: ...

    @staticmethod
    def toString(c: ghidra.program.model.data.DataTypeComponent) -> unicode: ...

    def update(self, ordinal: int, offset: int, length: int) -> None:
        """
        Update component ordinal, offset and length during alignment
        @param ordinal updated ordinal
        @param offset updated offset
        @param length updated byte length
        """
        ...

    @staticmethod
    def usesZeroLengthComponent(__a0: ghidra.program.model.data.DataType) -> bool: ...

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

    @dataType.setter
    def dataType(self, value: ghidra.program.model.data.DataType) -> None: ...

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