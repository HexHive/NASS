from typing import List
import ghidra.util.exception
import java.io
import java.lang
import java.nio


class StringRenderParser(object):
    """
    A parser to invert StringDataInstance#getStringRepresentation(),
     StringDataInstance#getCharRepresentation(), and related.
    """






    class StringParseException(ghidra.util.exception.UsrException):




        @overload
        def __init__(self, __a0: int): ...

        @overload
        def __init__(self, __a0: int, __a1: java.util.Set, __a2: int): ...



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



    def __init__(self, quoteChar: int, endian: ghidra.program.model.lang.Endian, charsetName: unicode, includeBOM: bool):
        """
        Construct a parser
        @param quoteChar the character expected to enclose the representation. Use double quote (")
                    for strings. Use single quote (') for characters.
        @param endian the endian for unicode strings
        @param charsetName the character set name, as in {@link Charset#forName(String)}
        @param includeBOM true to prepend a byte order marker, if applicable
        """
        ...



    def equals(self, __a0: object) -> bool: ...

    def finish(self, out: java.nio.ByteBuffer) -> None:
        """
        Finish parsing and encoded a string or character representation
        @param out the destination buffer for the encoded string or character
        @throws StringParseException if the representation is not complete
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @overload
    def parse(self, in_: java.nio.CharBuffer) -> java.nio.ByteBuffer:
        """
        Parse and encode a complete string or character representation
        @param in the buffer containing the representation
        @return a buffer containing the encoded string or character
        @throws StringParseException if the representation could not be parsed
        @throws MalformedInputException if a character sequence in the representation is not valid
        @throws UnmappableCharacterException if a character cannot be encoded
        """
        ...

    @overload
    def parse(self, out: java.nio.ByteBuffer, in_: java.nio.CharBuffer) -> None:
        """
        Parse and encode a portion of a string or character representation
        @param out the destination buffer for the encoded string or character, having matching byte
                    order to the charset.
        @param in the source buffer for the representation
        @throws StringParseException if the representation could not be parsed
        @throws MalformedInputException if a character sequence in the representation is not valid
        @throws UnmappableCharacterException if a character cannot be encoded
        """
        ...

    def reset(self) -> None:
        """
        Reset the parser
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

