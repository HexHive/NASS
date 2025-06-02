from typing import List
import ghidra.util.exception
import java.io
import java.lang


class GhidraScriptLoadException(ghidra.util.exception.UsrException):
    """
    An exception for when a script provider cannot create a script instance
    """





    @overload
    def __init__(self, message: unicode):
        """
        Construct an exception with a message
        @param message the error message including details and possible remedies
        """
        ...

    @overload
    def __init__(self, cause: java.lang.Throwable):
        """
        Construct an exception with a cause
 
         <p>
         This will copy the cause's message into this exception's message.
        @param cause the exception causing this one
        """
        ...

    @overload
    def __init__(self, message: unicode, cause: java.lang.Throwable):
        """
        Construct an exception with a custom message and cause
 
         <p>
         Note that the error message displayed to the user does not automatically include details from
         the cause. The client must provide details from the cause in the message as needed.
        @param message the error message including details and possible remedies
        @param cause the exception causing this one
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

