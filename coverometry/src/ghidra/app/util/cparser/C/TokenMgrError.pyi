from typing import List
import java.io
import java.lang


class TokenMgrError(java.lang.Error):
    """
    Token Manager Error.
    """





    @overload
    def __init__(self):
        """
        No arg constructor.
        """
        ...

    @overload
    def __init__(self, message: unicode, reason: int):
        """
        Constructor with message and reason.
        """
        ...

    @overload
    def __init__(self, EOFSeen: bool, lexState: int, errorLine: int, errorColumn: int, errorAfter: unicode, curChar: int, reason: int):
        """
        Full Constructor.
        """
        ...



    def addSuppressed(self, __a0: java.lang.Throwable) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def fillInStackTrace(self) -> java.lang.Throwable: ...

    def getCause(self) -> java.lang.Throwable: ...

    def getClass(self) -> java.lang.Class: ...

    def getLocalizedMessage(self) -> unicode: ...

    def getMessage(self) -> unicode:
        """
        You can also modify the body of this method to customize your error messages.
         For example, cases like LOOP_DETECTED and INVALID_LEXICAL_STATE are not
         of end-users concern, so you can return something like :

             "Internal Error : Please file a bug report .... "

         from this method for such cases in the release version of your parser.
        """
        ...

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

    @property
    def message(self) -> unicode: ...