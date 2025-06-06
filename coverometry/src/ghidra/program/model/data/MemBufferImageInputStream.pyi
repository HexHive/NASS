from typing import List
import java.lang
import java.nio
import javax.imageio.stream


class MemBufferImageInputStream(javax.imageio.stream.ImageInputStreamImpl):
    """
    ImageInputStream for reading images that wraps a MemBuffer to get the bytes.  Adds a method
     to find out how many bytes were read by the imageReader to read the image.
    """





    def __init__(self, buf: ghidra.program.model.mem.MemBuffer, byteOrder: java.nio.ByteOrder): ...



    def close(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def flush(self) -> None: ...

    def flushBefore(self, __a0: long) -> None: ...

    def getBitOffset(self) -> int: ...

    def getByteOrder(self) -> java.nio.ByteOrder: ...

    def getClass(self) -> java.lang.Class: ...

    def getConsumedLength(self) -> int: ...

    def getFlushedPosition(self) -> long: ...

    def getStreamPosition(self) -> long: ...

    def hashCode(self) -> int: ...

    def isCached(self) -> bool: ...

    def isCachedFile(self) -> bool: ...

    def isCachedMemory(self) -> bool: ...

    def length(self) -> long: ...

    def mark(self) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @overload
    def read(self) -> int: ...

    @overload
    def read(self, __a0: List[int]) -> int: ...

    @overload
    def read(self, b: List[int], off: int, len: int) -> int: ...

    def readBit(self) -> int: ...

    def readBits(self, __a0: int) -> long: ...

    def readBoolean(self) -> bool: ...

    def readByte(self) -> int: ...

    def readBytes(self, __a0: javax.imageio.stream.IIOByteBuffer, __a1: int) -> None: ...

    def readChar(self) -> int: ...

    def readDouble(self) -> float: ...

    def readFloat(self) -> float: ...

    @overload
    def readFully(self, __a0: List[int]) -> None: ...

    @overload
    def readFully(self, __a0: List[long], __a1: int, __a2: int) -> None: ...

    @overload
    def readFully(self, __a0: List[int], __a1: int, __a2: int) -> None: ...

    @overload
    def readFully(self, __a0: List[int], __a1: int, __a2: int) -> None: ...

    @overload
    def readFully(self, __a0: List[int], __a1: int, __a2: int) -> None: ...

    @overload
    def readFully(self, __a0: List[int], __a1: int, __a2: int) -> None: ...

    @overload
    def readFully(self, __a0: List[float], __a1: int, __a2: int) -> None: ...

    @overload
    def readFully(self, __a0: List[float], __a1: int, __a2: int) -> None: ...

    def readInt(self) -> int: ...

    def readLine(self) -> unicode: ...

    def readLong(self) -> long: ...

    def readShort(self) -> int: ...

    def readUTF(self) -> unicode: ...

    def readUnsignedByte(self) -> int: ...

    def readUnsignedInt(self) -> long: ...

    def readUnsignedShort(self) -> int: ...

    def reset(self) -> None: ...

    def seek(self, __a0: long) -> None: ...

    def setBitOffset(self, __a0: int) -> None: ...

    def setByteOrder(self, __a0: java.nio.ByteOrder) -> None: ...

    @overload
    def skipBytes(self, __a0: long) -> long: ...

    @overload
    def skipBytes(self, __a0: int) -> int: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def consumedLength(self) -> int: ...