from typing import List
import java.io
import java.lang


class MemBufferInputStream(java.io.InputStream):
    """
    Adapter between MemBuffer and InputStream.
    """





    @overload
    def __init__(self, membuf: ghidra.program.model.mem.MemBuffer):
        """
        Creates a new instance, starting a offset 0 of the membuffer, limited to the first 2Gb
         of the membuffer.
        @param membuf {@link MemBuffer} to wrap as an inputstream
        """
        ...

    @overload
    def __init__(self, membuf: ghidra.program.model.mem.MemBuffer, initialPosition: int, length: int):
        """
        Creates a new instance of {@link MemBufferInputStream}, starting at the specified offset,
         limited to the first {@code length} bytes.
        @param membuf {@link MemBuffer} to wrap as an inputstream
        @param initialPosition starting position in the membuffer
        @param length number of bytes to limit this inputstream to.  The sum of 
         {@code initialPosition} and {@code length} must not exceed {@link Integer#MAX_VALUE}+1
        """
        ...



    def available(self) -> int: ...

    def close(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def mark(self, __a0: int) -> None: ...

    def markSupported(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def nullInputStream() -> java.io.InputStream: ...

    @overload
    def read(self) -> int: ...

    @overload
    def read(self, __a0: List[int]) -> int: ...

    @overload
    def read(self, __a0: List[int], __a1: int, __a2: int) -> int: ...

    def readAllBytes(self) -> List[int]: ...

    @overload
    def readNBytes(self, __a0: int) -> List[int]: ...

    @overload
    def readNBytes(self, __a0: List[int], __a1: int, __a2: int) -> int: ...

    def reset(self) -> None: ...

    def skip(self, __a0: long) -> long: ...

    def skipNBytes(self, __a0: long) -> None: ...

    def toString(self) -> unicode: ...

    def transferTo(self, __a0: java.io.OutputStream) -> long: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

