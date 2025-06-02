import ghidra.app.util.bin.format.coff
import ghidra.app.util.bin.format.coff.relocation
import ghidra.program.model.address
import ghidra.program.model.reloc
import java.lang


class X86_32_CoffRelocationHandler(object, ghidra.app.util.bin.format.coff.relocation.CoffRelocationHandler):
    IMAGE_REL_I386_ABSOLUTE: int = 0
    IMAGE_REL_I386_DIR16: int = 1
    IMAGE_REL_I386_DIR32: int = 6
    IMAGE_REL_I386_DIR32NB: int = 7
    IMAGE_REL_I386_REL16: int = 2
    IMAGE_REL_I386_REL32: int = 20
    IMAGE_REL_I386_SECREL: int = 11
    IMAGE_REL_I386_SECREL7: int = 13
    IMAGE_REL_I386_SECTION: int = 10
    IMAGE_REL_I386_SEG12: int = 9
    IMAGE_REL_I386_TOKEN: int = 12



    def __init__(self): ...



    def canRelocate(self, __a0: ghidra.app.util.bin.format.coff.CoffFileHeader) -> bool: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def relocate(self, __a0: ghidra.program.model.address.Address, __a1: ghidra.app.util.bin.format.coff.CoffRelocation, __a2: ghidra.app.util.bin.format.coff.relocation.CoffRelocationContext) -> ghidra.program.model.reloc.RelocationResult: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

