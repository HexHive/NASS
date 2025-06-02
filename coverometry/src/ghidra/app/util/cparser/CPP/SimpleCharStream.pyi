from typing import List
import java.io
import java.lang


class SimpleCharStream(object):
    """
    An implementation of interface CharStream, where the stream is assumed to
     contain only ASCII characters (without unicode processing).
    """

    bufpos: int
    staticFlag: bool = False



    @overload
    def __init__(self, dstream: java.io.InputStream):
        """
        Constructor.
        """
        ...

    @overload
    def __init__(self, dstream: java.io.Reader):
        """
        Constructor.
        """
        ...

    @overload
    def __init__(self, dstream: java.io.InputStream, encoding: unicode):
        """
        Constructor.
        """
        ...

    @overload
    def __init__(self, dstream: java.io.InputStream, startline: int, startcolumn: int):
        """
        Constructor.
        """
        ...

    @overload
    def __init__(self, dstream: java.io.Reader, startline: int, startcolumn: int):
        """
        Constructor.
        """
        ...

    @overload
    def __init__(self, dstream: java.io.InputStream, startline: int, startcolumn: int, buffersize: int):
        """
        Constructor.
        """
        ...

    @overload
    def __init__(self, dstream: java.io.Reader, startline: int, startcolumn: int, buffersize: int):
        """
        Constructor.
        """
        ...

    @overload
    def __init__(self, dstream: java.io.InputStream, encoding: unicode, startline: int, startcolumn: int):
        """
        Constructor.
        """
        ...

    @overload
    def __init__(self, dstream: java.io.InputStream, encoding: unicode, startline: int, startcolumn: int, buffersize: int):
        """
        Constructor.
        """
        ...



    def BeginToken(self) -> int:
        """
        Start.
        """
        ...

    def Done(self) -> None:
        """
        Reset buffer when finished.
        """
        ...

    def GetImage(self) -> unicode:
        """
        Get token literal value.
        """
        ...

    def GetSuffix(self, len: int) -> List[int]:
        """
        Get the suffix.
        """
        ...

    @overload
    def ReInit(self, dstream: java.io.InputStream) -> None:
        """
        Reinitialise.
        """
        ...

    @overload
    def ReInit(self, dstream: java.io.Reader) -> None:
        """
        Reinitialise.
        """
        ...

    @overload
    def ReInit(self, dstream: java.io.InputStream, encoding: unicode) -> None:
        """
        Reinitialise.
        """
        ...

    @overload
    def ReInit(self, dstream: java.io.InputStream, startline: int, startcolumn: int) -> None:
        """
        Reinitialise.
        """
        ...

    @overload
    def ReInit(self, dstream: java.io.Reader, startline: int, startcolumn: int) -> None:
        """
        Reinitialise.
        """
        ...

    @overload
    def ReInit(self, dstream: java.io.InputStream, startline: int, startcolumn: int, buffersize: int) -> None:
        """
        Reinitialise.
        """
        ...

    @overload
    def ReInit(self, dstream: java.io.Reader, startline: int, startcolumn: int, buffersize: int) -> None:
        """
        Reinitialise.
        """
        ...

    @overload
    def ReInit(self, dstream: java.io.InputStream, encoding: unicode, startline: int, startcolumn: int) -> None:
        """
        Reinitialise.
        """
        ...

    @overload
    def ReInit(self, dstream: java.io.InputStream, encoding: unicode, startline: int, startcolumn: int, buffersize: int) -> None:
        """
        Reinitialise.
        """
        ...

    def adjustBeginLineColumn(self, newLine: int, newCol: int) -> None:
        """
        Method to adjust line and column numbers for the start of a token.
        """
        ...

    def backup(self, amount: int) -> None:
        """
        Backup a number of characters.
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getBeginColumn(self) -> int:
        """
        Get token beginning column number.
        """
        ...

    def getBeginLine(self) -> int:
        """
        Get token beginning line number.
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getColumn(self) -> int: ...

    def getEndColumn(self) -> int:
        """
        Get token end column number.
        """
        ...

    def getEndLine(self) -> int:
        """
        Get token end line number.
        """
        ...

    def getLine(self) -> int: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def readChar(self) -> int:
        """
        Read a character.
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def beginColumn(self) -> int: ...

    @property
    def beginLine(self) -> int: ...

    @property
    def column(self) -> int: ...

    @property
    def endColumn(self) -> int: ...

    @property
    def endLine(self) -> int: ...

    @property
    def line(self) -> int: ...