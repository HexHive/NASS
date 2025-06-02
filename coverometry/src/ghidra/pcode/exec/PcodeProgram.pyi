from typing import List
import ghidra.app.plugin.processors.sleigh
import ghidra.pcode.exec
import ghidra.program.model.listing
import java.lang


class PcodeProgram(object):








    def equals(self, __a0: object) -> bool: ...

    def execute(self, __a0: ghidra.pcode.exec.PcodeExecutor, __a1: ghidra.pcode.exec.PcodeUseropLibrary) -> None: ...

    @staticmethod
    def fromInject(__a0: ghidra.program.model.listing.Program, __a1: unicode, __a2: int) -> ghidra.pcode.exec.PcodeProgram: ...

    @overload
    @staticmethod
    def fromInstruction(__a0: ghidra.program.model.listing.Instruction) -> ghidra.pcode.exec.PcodeProgram: ...

    @overload
    @staticmethod
    def fromInstruction(__a0: ghidra.program.model.listing.Instruction, __a1: bool) -> ghidra.pcode.exec.PcodeProgram: ...

    def getClass(self) -> java.lang.Class: ...

    def getCode(self) -> List[object]: ...

    def getLanguage(self) -> ghidra.app.plugin.processors.sleigh.SleighLanguage: ...

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
    def code(self) -> List[object]: ...

    @property
    def language(self) -> ghidra.app.plugin.processors.sleigh.SleighLanguage: ...