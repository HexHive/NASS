from typing import List
import ghidra.app.util.datatype.microsoft
import ghidra.program.model.address
import java.lang
import java.util


class ThreadEnvironmentBlock(object):
    """
    Class for creating a Ghidra memory block representing the TEB: Thread Environment Block.
     The class must be instantiated with the Program and the Windows OS version to control
     details of the TEB layout.  The user must call setAddress to provide the starting address
     of the block to create. Then they must call one of
        - createBlockAndStructure    or
        - createBlocksAndSymbols
 
     The TEB can be represented either by a single structure overlaying the
     block (createBlockAndStructure), or as a series of symbols and primitive
     data-types (createBlocksAndSymbols).
 
     Finally the user should call setRegisterValue. The TEB is accessed either through the FS segment
     (32-bit) or GS segment (64-bit), so this method sets a Register value for one these over
     the program.
    """

    BLOCK_NAME: unicode = u'tdb'




    class WinVersion(java.lang.Enum):
        WIN_10: ghidra.app.util.datatype.microsoft.ThreadEnvironmentBlock.WinVersion = Windows 10
        WIN_2000: ghidra.app.util.datatype.microsoft.ThreadEnvironmentBlock.WinVersion = Windows 2000
        WIN_3_10: ghidra.app.util.datatype.microsoft.ThreadEnvironmentBlock.WinVersion = Windows 3.10
        WIN_3_50: ghidra.app.util.datatype.microsoft.ThreadEnvironmentBlock.WinVersion = Windows 3.50
        WIN_7: ghidra.app.util.datatype.microsoft.ThreadEnvironmentBlock.WinVersion = Windows 7
        WIN_95: ghidra.app.util.datatype.microsoft.ThreadEnvironmentBlock.WinVersion = Windows 95
        WIN_LATEST: ghidra.app.util.datatype.microsoft.ThreadEnvironmentBlock.WinVersion = Latest
        WIN_VISTA: ghidra.app.util.datatype.microsoft.ThreadEnvironmentBlock.WinVersion = Windows Vista
        WIN_XP: ghidra.app.util.datatype.microsoft.ThreadEnvironmentBlock.WinVersion = Windows XP







        @overload
        def compareTo(self, __a0: java.lang.Enum) -> int: ...

        @overload
        def compareTo(self, __a0: object) -> int: ...

        def describeConstable(self) -> java.util.Optional: ...

        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def getDeclaringClass(self) -> java.lang.Class: ...

        def getOrder(self) -> int: ...

        def hashCode(self) -> int: ...

        def name(self) -> unicode: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def ordinal(self) -> int: ...

        def toString(self) -> unicode: ...

        @overload
        @staticmethod
        def valueOf(__a0: unicode) -> ghidra.app.util.datatype.microsoft.ThreadEnvironmentBlock.WinVersion: ...

        @overload
        @staticmethod
        def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

        @staticmethod
        def values() -> List[ghidra.app.util.datatype.microsoft.ThreadEnvironmentBlock.WinVersion]: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...

        @property
        def order(self) -> int: ...

    def __init__(self, prog: ghidra.program.model.listing.Program, version: ghidra.app.util.datatype.microsoft.ThreadEnvironmentBlock.WinVersion): ...



    def createBlockAndStructure(self) -> None:
        """
        Create TEB as a single uninitialized block.  A TEB structure is created and is
         placed on the block.
        @throws MemoryConflictException if there are overlap problems with other blocks
        @throws AddressOverflowException for problems with block's start Address
        @throws IllegalArgumentException for problems with the block name or the TEB data-type
        @throws LockException if it cannot get an exclusive lock on the program
        @throws CodeUnitInsertionException for problems laying down the structure on the block
        @throws InvalidInputException for problems with the symbol name attached to the TEB
        """
        ...

    def createBlocksAndSymbols(self) -> None:
        """
        Create 2 blocks, one that is initialized to hold a proper value for the TEB Self reference field
         and another to hold the remainder of the TEB.  The data structure is layed down as a
         series of symbols on these blocks.
        @throws MemoryConflictException if there are overlap problems with other blocks
        @throws CancelledException if block creation is cancelled
        @throws AddressOverflowException for problems with block's start Address
        @throws IllegalArgumentException for problems with the block name or the TEB data-type
        @throws LockException if it cannot get an exclusive lock on the program
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getBlockSize(self) -> int:
        """
        @return the number of bytes needed in the full TEB block being constructed
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def is64(self) -> bool:
        """
        @return true if a 64-bit TEB is being layed down.
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setAddress(self, addr: ghidra.program.model.address.Address) -> None:
        """
        Set the starting address of the TEB
        @param addr is the Address to set
        """
        ...

    def setRegisterValue(self) -> None:
        """
        Set FS_OFFSET for 32-bit or GS_OFFSET for 64-bit to the address of the TEB across the program.
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
    def 64(self) -> bool: ...

    @property
    def address(self) -> None: ...  # No getter available.

    @address.setter
    def address(self, value: ghidra.program.model.address.Address) -> None: ...

    @property
    def blockSize(self) -> int: ...