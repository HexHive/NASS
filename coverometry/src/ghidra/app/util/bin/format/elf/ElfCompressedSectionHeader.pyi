import ghidra.app.util.bin
import ghidra.app.util.bin.format.elf
import java.lang


class ElfCompressedSectionHeader(object):
    """
    Header at the beginning of an ELF compressed section.
 
     See https://docs.oracle.com/cd/E53394_01/html/E54813/section_compression.html
 
 
     typedef struct {
          Elf32_Word      ch_type;
          Elf32_Word      ch_size;
          Elf32_Word      ch_addralign;
     } Elf32_Chdr;
 
     typedef struct {
          Elf64_Word      ch_type;
          Elf64_Word      ch_reserved;
          Elf64_Xword     ch_size;
          Elf64_Xword     ch_addralign;
     } Elf64_Chdr;
 
    """

    ELFCOMPRESS_ZLIB: int = 1







    def equals(self, __a0: object) -> bool: ...

    def getCh_addralign(self) -> long:
        """
        {@return the address alignment value}.
         <p>
         See {@link ElfSectionHeader#getAddressAlignment()}
        """
        ...

    def getCh_size(self) -> long:
        """
        {@return the uncompressed size}
        """
        ...

    def getCh_type(self) -> int:
        """
        {@return the compression type, see ELFCOMPRESS_ZLIB}
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getHeaderSize(self) -> int:
        """
        {@return the size of this header struct}
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def read(reader: ghidra.app.util.bin.BinaryReader, elf: ghidra.app.util.bin.format.elf.ElfHeader) -> ghidra.app.util.bin.format.elf.ElfCompressedSectionHeader:
        """
        Reads an Elf(32|64)_Chdr from the current position in the supplied stream.
        @param reader stream to read from
        @param elf ElfHeader that defines the format of the binary
        @return new {@link ElfCompressedSectionHeader} instance, never null
        @throws IOException if error reading the header
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
    def ch_addralign(self) -> long: ...

    @property
    def ch_size(self) -> long: ...

    @property
    def ch_type(self) -> int: ...

    @property
    def headerSize(self) -> int: ...