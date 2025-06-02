import ghidra.pcode.emu.sys
import ghidra.pcode.exec
import java.lang


class UseropEmuSyscallDefinition(object, ghidra.pcode.emu.sys.EmuSyscallLibrary.EmuSyscallDefinition):




    def __init__(self, __a0: ghidra.pcode.exec.PcodeUseropLibrary.PcodeUseropDefinition, __a1: ghidra.program.model.listing.Program, __a2: ghidra.program.model.lang.PrototypeModel, __a3: ghidra.program.model.data.DataType): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def invoke(self, __a0: ghidra.pcode.exec.PcodeExecutor, __a1: ghidra.pcode.exec.PcodeUseropLibrary) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

