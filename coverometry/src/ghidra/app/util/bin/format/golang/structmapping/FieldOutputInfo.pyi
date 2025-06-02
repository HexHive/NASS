import ghidra.app.util.bin.format.golang.structmapping
import java.lang
import java.lang.reflect


class FieldOutputInfo(object):
    """
    Immutable information needed to create fields in a Ghidra structure data type, using information
     from a java field.
    """





    def __init__(self, fmi: ghidra.app.util.bin.format.golang.structmapping.FieldMappingInfo, dataTypeName: unicode, isVariableLength: bool, ordinal: int, fieldOffset: int): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getField(self) -> java.lang.reflect.Field: ...

    def getOrdinal(self) -> int: ...

    def getOutputFunc(self) -> ghidra.app.util.bin.format.golang.structmapping.FieldOutputFunction: ...

    def getValue(self, structInstance: object, expectedType: java.lang.Class) -> R:
        """
        Returns the value of this java field.
        @param <R> type of the result value
        @param structInstance object containing the field
        @param expectedType expected class of the value
        @return value of the field, or null if the field's value is not of expected type
        @throws IOException if error accessing java field
        """
        ...

    def hashCode(self) -> int: ...

    def isVariableLength(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setOutputFuncClass(self, funcClass: java.lang.Class, getterName: unicode) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def field(self) -> java.lang.reflect.Field: ...

    @property
    def ordinal(self) -> int: ...

    @property
    def outputFunc(self) -> ghidra.app.util.bin.format.golang.structmapping.FieldOutputFunction: ...

    @property
    def variableLength(self) -> bool: ...