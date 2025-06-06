from typing import List
import ghidra.pcode.exec
import ghidra.program.model.address
import ghidra.program.model.lang
import java.io
import java.lang


class UnknownStatePcodeExecutionException(ghidra.pcode.exec.AccessPcodeExecutionException):




    @overload
    def __init__(self, __a0: ghidra.program.model.lang.Language, __a1: ghidra.program.model.address.Address, __a2: int): ...

    @overload
    def __init__(self, __a0: unicode, __a1: ghidra.program.model.lang.Language, __a2: ghidra.program.model.address.Address, __a3: int): ...



    def addSuppressed(self, __a0: java.lang.Throwable) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def fillInStackTrace(self) -> java.lang.Throwable: ...

    def getCause(self) -> java.lang.Throwable: ...

    def getClass(self) -> java.lang.Class: ...

    def getFrame(self) -> ghidra.pcode.exec.PcodeFrame: ...

    def getLocalizedMessage(self) -> unicode: ...

    @overload
    def getMessage(self) -> unicode: ...

    @overload
    @staticmethod
    def getMessage(__a0: ghidra.program.model.lang.Language, __a1: ghidra.program.model.address.Address, __a2: int) -> unicode: ...

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

