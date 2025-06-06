from typing import List
import ghidra.util.exception
import java.io
import java.lang


class MemoryAccessException(ghidra.util.exception.UsrException):
    """
    An MemoryAccessException indicates that the attempted
     memory access is not permitted.  (i.e. Readable/Writeable)
    """





    @overload
    def __init__(self):
        """
        <p>Constructs an MemoryAccessException with no detail message.<p>
        """
        ...

    @overload
    def __init__(self, message: unicode):
        """
        <p>Constructs an MemoryAccessException with the specified
         detail message.<p>
        @param message The message.
        """
        ...

    @overload
    def __init__(self, msg: unicode, cause: java.lang.Throwable):
        """
        Creates a {@link MemoryAccessException} with a message and cause.
        @param msg message
        @param cause nested cause
        """
        ...



    def addSuppressed(self, __a0: java.lang.Throwable) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def fillInStackTrace(self) -> java.lang.Throwable: ...

    def getCause(self) -> java.lang.Throwable: ...

    def getClass(self) -> java.lang.Class: ...

    def getLocalizedMessage(self) -> unicode: ...

    def getMessage(self) -> unicode: ...

    def getStackTrace(self) -> List[java.lang.StackTraceElement]: ...

    def getSuppressed(self) -> List[java.lang.Throwable]: ...

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

