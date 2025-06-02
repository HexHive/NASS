from typing import List
import ghidra.framework
import java.io
import java.lang


class OSFileNotFoundException(java.io.FileNotFoundException):
    """
    Signals that an attempt to find a Ghidra "OS-file" (native binary) has failed.
 
     This exception provides a consistent way to display information about the missing OS-file that 
     will aid in error reporting and debugging.
    """





    @overload
    def __init__(self, fileName: unicode):
        """
        Creates a new {@link OSFileNotFoundException} for the current {@link Platform} with an
         unknown module
        @param fileName The file name associated with this exception, from an unknown module
        """
        ...

    @overload
    def __init__(self, moduleName: unicode, fileName: unicode):
        """
        Creates a new {@link OSFileNotFoundException} for the current {@link Platform}
        @param moduleName The module name associated with this exception
        @param fileName The file name associated with this exception, from the given module
        """
        ...

    @overload
    def __init__(self, platform: ghidra.framework.Platform, fileName: unicode):
        """
        Creates a new {@link OSFileNotFoundException} with an unknown module
        @param platform The {@link Platform} associated with this exception
        @param fileName The file name associated with this exception, from an unknown module
        """
        ...

    @overload
    def __init__(self, platform: ghidra.framework.Platform, moduleName: unicode, fileName: unicode):
        """
        Creates a new {@link OSFileNotFoundException}
        @param platform The {@link Platform} associated with this exception
        @param moduleName The module name associated with this exception
        @param fileName The file name associated with this exception, from the given module
        """
        ...



    def addSuppressed(self, __a0: java.lang.Throwable) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def fillInStackTrace(self) -> java.lang.Throwable: ...

    def getCause(self) -> java.lang.Throwable: ...

    def getClass(self) -> java.lang.Class: ...

    def getLocalizedMessage(self) -> unicode: ...

    def getMessage(self) -> unicode: ...

    def getPlatform(self) -> ghidra.framework.Platform:
        """
        Gets the {@link Platform} associated with this exception
        @return The {@link Platform} associated with this exception
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
    def platform(self) -> ghidra.framework.Platform: ...