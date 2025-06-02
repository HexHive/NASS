import ghidra.program.model.data
import java.lang


class FieldMatcher(object):
    """
    This class allows clients to match on multiple field attributes, such as name and offset
     within a parent data type.
 
     Use #FieldMatcher(DataType) as an 'empty' or 'ignored' field matcher to signal that any
     field match is considered value.
    """





    @overload
    def __init__(self, dataType: ghidra.program.model.data.DataType):
        """
        Creates an 'empty' matcher that can be used to signal no specific field or offset match
         is required.
        @param dataType the non-null data type.
        """
        ...

    @overload
    def __init__(self, dataType: ghidra.program.model.data.DataType, offset: int): ...

    @overload
    def __init__(self, dataType: ghidra.program.model.data.DataType, fieldName: unicode): ...



    def equals(self, obj: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDataType(self) -> ghidra.program.model.data.DataType: ...

    def getDisplayText(self) -> unicode:
        """
        Returns a display text for this field matcher, for example, {@code Foo.bar}.
        @return the display text
        """
        ...

    def getFieldName(self) -> unicode:
        """
        Returns the field name given to this matcher or will attempt to generate a default field
         name using the given data type and offset.
        @return the field name or null
        """
        ...

    def hashCode(self) -> int: ...

    def isIgnored(self) -> bool:
        """
        Signals that no specific field match is required.
        @return true if no field or offset has been specified.
        """
        ...

    def matches(self, dtFieldName: unicode, dtOffset: int) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def dataType(self) -> ghidra.program.model.data.DataType: ...

    @property
    def displayText(self) -> unicode: ...

    @property
    def fieldName(self) -> unicode: ...

    @property
    def ignored(self) -> bool: ...