from typing import List
import ghidra.app.util.bin
import ghidra.app.util.bin.format.elf.info
import ghidra.program.model.address
import ghidra.program.model.listing
import java.lang


class ElfComment(object, ghidra.app.util.bin.format.elf.info.ElfInfoItem):
    """
    An Elf section that contains null-terminated strings, typically added by the compiler to
     the binary
    """

    SECTION_NAME: unicode = u'.comment'



    def __init__(self, __a0: List[object], __a1: List[object]): ...



    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def fromProgram(program: ghidra.program.model.listing.Program) -> ghidra.app.util.bin.format.elf.info.ElfComment:
        """
        Reads an ElfComment from the standard ".comment" section in the specified Program.
        @param program Program to read from
        @return new instance, or null if not found or data error
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getCommentStrings(self) -> List[unicode]: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def markupElfInfoItemSection(__a0: ghidra.program.model.listing.Program, __a1: unicode, __a2: ghidra.app.util.bin.format.elf.info.ElfInfoItem.ReaderFunc) -> None: ...

    def markupProgram(self, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def read(br: ghidra.app.util.bin.BinaryReader, program: ghidra.program.model.listing.Program) -> ghidra.app.util.bin.format.elf.info.ElfComment:
        """
        Reads a ElfComment from the specified BinaryReader.
        @param br BinaryReader to read from
        @param program unused, present to match the signature of {@link ElfInfoItem.ReaderFunc}
        @return new instance, or null if data error
        """
        ...

    @staticmethod
    def readItemFromSection(__a0: ghidra.program.model.listing.Program, __a1: unicode, __a2: ghidra.app.util.bin.format.elf.info.ElfInfoItem.ReaderFunc) -> ghidra.app.util.bin.format.elf.info.ElfInfoItem.ItemWithAddress: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def commentStrings(self) -> List[object]: ...