from typing import List
import ghidra.app.util.bin
import ghidra.app.util.bin.format.mz
import java.lang


class MzExecutable(object):
    """
    A class to manage loading old-style DOS MZ executables
    """





    def __init__(self, provider: ghidra.app.util.bin.ByteProvider):
        """
        Constructs a new instance of an old-style MZ executable
        @param provider The bytes
        @throws IOException if an I/O error occurs
        """
        ...



    def equals(self, __a0: object) -> bool: ...

    def getBinaryReader(self) -> ghidra.app.util.bin.BinaryReader:
        """
        Returns the underlying binary reader
        @return the underlying binary reader
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getHeader(self) -> ghidra.app.util.bin.format.mz.OldDOSHeader:
        """
        Returns the DOS Header from this old-style MZ executable
        @return the DOS Header from this old-style MZ executable
        """
        ...

    def getRelocations(self) -> List[ghidra.app.util.bin.format.mz.MzRelocation]:
        """
        Returns the old-style MZ relocations
        @return the old-style MZ relocations
        """
        ...

    def hashCode(self) -> int: ...

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
    def binaryReader(self) -> ghidra.app.util.bin.BinaryReader: ...

    @property
    def header(self) -> ghidra.app.util.bin.format.mz.OldDOSHeader: ...

    @property
    def relocations(self) -> List[object]: ...