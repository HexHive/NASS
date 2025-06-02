from typing import List
import ghidra.program.model.address
import ghidra.program.model.mem
import java.io
import java.lang


class ByteMemBufferImpl(object, ghidra.program.model.mem.MemBuffer):
    """
    Simple byte buffer implementation of the memBuffer.  Even if a Memory is
     provided, the available bytes will be limited to the bytes provided during
     construction.
    """





    @overload
    def __init__(self, addr: ghidra.program.model.address.Address, bytes: List[int], isBigEndian: bool):
        """
        Construct a ByteMemBufferImpl object
        @param addr the address to associate with the bytes
        @param bytes the data that normally would be coming from memory.
        @param isBigEndian true for BigEndian, false for LittleEndian.
        """
        ...

    @overload
    def __init__(self, memory: ghidra.program.model.mem.Memory, addr: ghidra.program.model.address.Address, bytes: List[int], isBigEndian: bool):
        """
        Construct a ByteMemBufferImpl object
        @param memory the memory in case getMemory() is called to get associated things like address spaces
        @param addr the address to associate with the bytes
        @param bytes the data that normally would be coming from memory.
        @param isBigEndian true for BigEndian, false for LittleEndian.
        """
        ...



    def equals(self, __a0: object) -> bool: ...

    def getAddress(self) -> ghidra.program.model.address.Address: ...

    def getBigInteger(self, offset: int, size: int, signed: bool) -> long: ...

    def getByte(self, offset: int) -> int: ...

    def getBytes(self, b: List[int], offset: int) -> int: ...

    def getClass(self) -> java.lang.Class: ...

    @overload
    def getInputStream(self) -> java.io.InputStream: ...

    @overload
    def getInputStream(self, __a0: int, __a1: int) -> java.io.InputStream: ...

    def getInt(self, offset: int) -> int: ...

    def getLength(self) -> int:
        """
        Get number of bytes contained within buffer
        @return byte count
        """
        ...

    def getLong(self, offset: int) -> long: ...

    def getMemory(self) -> ghidra.program.model.mem.Memory: ...

    def getShort(self, offset: int) -> int: ...

    def getUnsignedByte(self, __a0: int) -> int: ...

    def getUnsignedInt(self, __a0: int) -> long: ...

    def getUnsignedShort(self, __a0: int) -> int: ...

    def getVarLengthInt(self, __a0: int, __a1: int) -> int: ...

    def getVarLengthUnsignedInt(self, __a0: int, __a1: int) -> long: ...

    def hashCode(self) -> int: ...

    def isBigEndian(self) -> bool: ...

    def isInitializedMemory(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def address(self) -> ghidra.program.model.address.Address: ...

    @property
    def bigEndian(self) -> bool: ...

    @property
    def initializedMemory(self) -> bool: ...

    @property
    def inputStream(self) -> java.io.InputStream: ...

    @property
    def length(self) -> int: ...

    @property
    def memory(self) -> ghidra.program.model.mem.Memory: ...