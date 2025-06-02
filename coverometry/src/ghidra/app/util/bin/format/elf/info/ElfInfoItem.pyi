import ghidra.app.util.bin
import ghidra.app.util.bin.format.elf.info
import ghidra.app.util.bin.format.elf.info.ElfInfoItem
import ghidra.program.model.address
import ghidra.program.model.listing
import java.lang


class ElfInfoItem(object):
    """
    Interface and helper functions to read and markup things that have been read from an
     Elf program.
    """






    class ReaderFunc(object):








        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def hashCode(self) -> int: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def read(self, __a0: ghidra.app.util.bin.BinaryReader, __a1: ghidra.program.model.listing.Program) -> ghidra.app.util.bin.format.elf.info.ElfInfoItem: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...






    class ItemWithAddress(java.lang.Record):




        def __init__(self, __a0: object, __a1: ghidra.program.model.address.Address): ...



        def address(self) -> ghidra.program.model.address.Address: ...

        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def hashCode(self) -> int: ...

        def item(self) -> object: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...







    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def markupElfInfoItemSection(program: ghidra.program.model.listing.Program, sectionName: unicode, readFunc: ghidra.app.util.bin.format.elf.info.ElfInfoItem.ReaderFunc) -> None:
        """
        Helper method to markup a program if it contains the specified item in the specified
         memory section.
        @param program {@link Program}
        @param sectionName name of memory section that contains the item
        @param readFunc {@link ReaderFunc} that will deserialize an instance of the item
        """
        ...

    def markupProgram(self, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address) -> None:
        """
        Markup a program's info and memory with this item.
        @param program {@link Program} to markup
        @param address {@link Address} of the item in the program
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def readItemFromSection(program: ghidra.program.model.listing.Program, sectionName: unicode, readFunc: ghidra.app.util.bin.format.elf.info.ElfInfoItem.ReaderFunc) -> ghidra.app.util.bin.format.elf.info.ElfInfoItem.ItemWithAddress:
        """
        Helper method to read an item from a program's memory section.
        @param <T> type of the item that will be read
        @param program {@link Program} to read from
        @param sectionName name of memory section that contains the item
        @param readFunc {@link ReaderFunc} that will deserialize an instance of the item
        @return a wrapped instance of the item, or null if the memory section does not exist
         or there was an error while reading the item from the section
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

