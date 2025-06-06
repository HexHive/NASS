from typing import List
import ghidra.app.util.bin.format.pdb2.pdbreader
import ghidra.framework.options
import java.io
import java.lang
import java.nio.charset


class PdbReaderOptions(java.lang.Exception):




    def __init__(self): ...



    def addSuppressed(self, __a0: java.lang.Throwable) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def fillInStackTrace(self) -> java.lang.Throwable: ...

    def getCause(self) -> java.lang.Throwable: ...

    def getClass(self) -> java.lang.Class: ...

    def getLocalizedMessage(self) -> unicode: ...

    def getMessage(self) -> unicode: ...

    def getOneByteCharset(self) -> java.nio.charset.Charset: ...

    def getOneByteCharsetName(self) -> unicode: ...

    @staticmethod
    def getOneByteCharsetNames() -> List[object]: ...

    def getStackTrace(self) -> List[java.lang.StackTraceElement]: ...

    def getSuppressed(self) -> List[java.lang.Throwable]: ...

    def getTwoByteCharset(self) -> java.nio.charset.Charset: ...

    def getTwoByteCharsetName(self) -> unicode: ...

    @staticmethod
    def getTwoByteCharsetNames() -> List[object]: ...

    def getWideCharCharset(self) -> java.nio.charset.Charset: ...

    def getWideCharCharsetName(self) -> unicode: ...

    def hashCode(self) -> int: ...

    def initCause(self, __a0: java.lang.Throwable) -> java.lang.Throwable: ...

    def loadOptions(self, __a0: ghidra.framework.options.Options) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @overload
    def printStackTrace(self) -> None: ...

    @overload
    def printStackTrace(self, __a0: java.io.PrintStream) -> None: ...

    @overload
    def printStackTrace(self, __a0: java.io.PrintWriter) -> None: ...

    def registerOptions(self, __a0: ghidra.framework.options.Options) -> None: ...

    def setDefaults(self) -> None: ...

    def setOneByteCharsetForName(self, __a0: unicode) -> ghidra.app.util.bin.format.pdb2.pdbreader.PdbReaderOptions: ...

    def setStackTrace(self, __a0: List[java.lang.StackTraceElement]) -> None: ...

    def setWideCharCharsetForName(self, __a0: unicode) -> ghidra.app.util.bin.format.pdb2.pdbreader.PdbReaderOptions: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def oneByteCharset(self) -> java.nio.charset.Charset: ...

    @property
    def oneByteCharsetForName(self) -> None: ...  # No getter available.

    @oneByteCharsetForName.setter
    def oneByteCharsetForName(self, value: unicode) -> None: ...

    @property
    def oneByteCharsetName(self) -> unicode: ...

    @property
    def twoByteCharset(self) -> java.nio.charset.Charset: ...

    @property
    def twoByteCharsetName(self) -> unicode: ...

    @property
    def wideCharCharset(self) -> java.nio.charset.Charset: ...

    @property
    def wideCharCharsetForName(self) -> None: ...  # No getter available.

    @wideCharCharsetForName.setter
    def wideCharCharsetForName(self, value: unicode) -> None: ...

    @property
    def wideCharCharsetName(self) -> unicode: ...