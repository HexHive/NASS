from typing import List
import ghidra.program.model.data
import ghidra.util.exception
import java.io
import java.lang


class DataTypeEncodeException(ghidra.util.exception.UsrException):
    """
    Exception thrown when a value cannot be encoded for a data type
    """





    @overload
    def __init__(self, value: object, dt: ghidra.program.model.data.DataType, cause: java.lang.Throwable):
        """
        Constructor
        @param value the requested value or representation
        @param dt the data type
        @param cause the exception cause
        """
        ...

    @overload
    def __init__(self, message: unicode, value: object, dt: ghidra.program.model.data.DataType):
        """
        Constructor
        @param message the exception message
        @param value the requested value or representation
        @param dt the data type
        """
        ...

    @overload
    def __init__(self, message: unicode, value: object, dt: ghidra.program.model.data.DataType, cause: java.lang.Throwable):
        """
        Constructor
        @param message the exception message
        @param value the requested value or representation
        @param dt the data type
        @param cause the exception cause
        """
        ...



    def addSuppressed(self, __a0: java.lang.Throwable) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def fillInStackTrace(self) -> java.lang.Throwable: ...

    def getCause(self) -> java.lang.Throwable: ...

    def getClass(self) -> java.lang.Class: ...

    def getDataType(self) -> ghidra.program.model.data.DataType:
        """
        Get the data type
        @return the data type
        """
        ...

    def getLocalizedMessage(self) -> unicode: ...

    def getMessage(self) -> unicode: ...

    def getStackTrace(self) -> List[java.lang.StackTraceElement]: ...

    def getSuppressed(self) -> List[java.lang.Throwable]: ...

    def getValue(self) -> object:
        """
        Get the requested value or representation
        @return the requested value representation
        """
        ...

    def hashCode(self) -> int: ...

    def initCause(self, __a0: java.lang.Throwable) -> java.lang.Throwable: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @overload
    def printStackTrace(self) -> None: ...

    @overload
    def printStackTrace(self, __a0: java.io.PrintStream) -> None: ...

    @overload
    def printStackTrace(self, __a0: java.io.PrintWriter) -> None: ...

    def setStackTrace(self, __a0: List[java.lang.StackTraceElement]) -> None: ...

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
    def value(self) -> object: ...