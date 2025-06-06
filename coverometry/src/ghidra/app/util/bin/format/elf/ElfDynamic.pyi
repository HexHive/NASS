import ghidra.app.util.bin.format.elf
import java.lang


class ElfDynamic(object):
    """
    A class to represent the Elf32_Dyn data structure.
 
 
     typedef  int32_t  Elf32_Sword;
     typedef uint32_t  Elf32_Word;
     typedef uint32_t  Elf32_Addr;
 
      typedef struct {
          Elf32_Sword     d_tag;
          union {
              Elf32_Word  d_val;
              Elf32_Addr  d_ptr;
          } d_un;
      } Elf32_Dyn;
 
     typedef   int64_t  Elf64_Sxword;
     typedef  uint64_t  Elf64_Xword;
     typedef  uint64_t  Elf64_Addr;
 
     typedef struct {
         Elf64_Sxword	   d_tag;     //Dynamic entry type
         union {
             Elf64_Xword d_val;     //Integer value
             Elf64_Addr  d_ptr;     //Address value
         } d_un;
     } Elf64_Dyn;
 
 
    """





    @overload
    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, elf: ghidra.app.util.bin.format.elf.ElfHeader): ...

    @overload
    def __init__(self, tag: int, value: long, elf: ghidra.app.util.bin.format.elf.ElfHeader):
        """
        Constructs a new ELF dynamic with the specified tag and value.
        @param tag the tag (or type) of this dynamic
        @param value the value (or pointer) of this dynamic
        @param elf the elf header
        """
        ...

    @overload
    def __init__(self, tag: ghidra.app.util.bin.format.elf.ElfDynamicType, value: long, elf: ghidra.app.util.bin.format.elf.ElfHeader):
        """
        Constructs a new ELF dynamic with the specified (enum) tag and value.
        @param tag the (enum) tag (or type) of this dynamic
        @param value the value (or pointer) of this dynamic
        @param elf the elf header
        """
        ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getTag(self) -> int:
        """
        Returns the value that controls the interpretation of the 
         the d_val and/or d_ptr.
        @return the tag (or type) of this dynamic
        """
        ...

    def getTagAsString(self) -> unicode:
        """
        A convenience method for getting a string representing the d_tag value.
         For example, if d_tag == DT_SYMTAB, then this method returns "DT_SYMTAB".
        @return a string representing the d_tag value
        """
        ...

    def getTagType(self) -> ghidra.app.util.bin.format.elf.ElfDynamicType:
        """
        Returns the enum value that controls the interpretation of the 
         the d_val and/or d_ptr (or null if unknown).
        @return the enum tag (or type) of this dynamic or null if unknown
        """
        ...

    def getValue(self) -> long:
        """
        Returns the object whose integer values represent various interpretations.
         For example, if d_tag == DT_SYMTAB, then d_val holds the address of the symbol table.
         But, if d_tag == DT_SYMENT, then d_val holds the size of each symbol entry.
        @return the Elf32_Word object represent integer values with various interpretations
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def sizeof(self) -> int:
        """
        @return the size in bytes of this object.
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
    def tag(self) -> int: ...

    @property
    def tagAsString(self) -> unicode: ...

    @property
    def tagType(self) -> ghidra.app.util.bin.format.elf.ElfDynamicType: ...

    @property
    def value(self) -> long: ...