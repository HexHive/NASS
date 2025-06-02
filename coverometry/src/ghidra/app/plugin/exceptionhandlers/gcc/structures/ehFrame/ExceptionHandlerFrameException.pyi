from typing import List
import java.io
import java.lang


class ExceptionHandlerFrameException(java.lang.Exception):
    """
    Generic Exception class for classes contained in the ehFrame package
    """





    @overload
    def __init__(self):
        """
        Constructs a new ExceptionHandlerFrameException with the specified detail message and
         cause.
        """
        ...

    @overload
    def __init__(self, message: unicode):
        """
        Constructs a new ExceptionHandlerFrameException with the specified detail message.
        @param message the detail message.
        """
        ...

    @overload
    def __init__(self, cause: java.lang.Throwable):
        """
        Constructs a new ExceptionHandlerFrameException with the specified cause.
        @param cause the cause of this exception being thrown.
        """
        ...

    @overload
    def __init__(self, message: unicode, cause: java.lang.Throwable):
        """
        Constructs a new ExceptionHandlerFrameException with the specified detail message and
         cause.
        @param message the detail message.
        @param cause the cause of this exception being thrown.
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

