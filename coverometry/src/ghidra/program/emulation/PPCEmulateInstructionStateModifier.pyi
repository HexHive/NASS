from typing import List
import ghidra.pcode.emulate
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.pcode
import java.lang


class PPCEmulateInstructionStateModifier(ghidra.pcode.emulate.EmulateInstructionStateModifier):




    def __init__(self, __a0: ghidra.pcode.emulate.Emulate): ...



    def equals(self, __a0: object) -> bool: ...

    def executeCallOther(self, __a0: ghidra.program.model.pcode.PcodeOp) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def initialExecuteCallback(self, __a0: ghidra.pcode.emulate.Emulate, __a1: ghidra.program.model.address.Address, __a2: ghidra.program.model.lang.RegisterValue) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def postExecuteCallback(self, __a0: ghidra.pcode.emulate.Emulate, __a1: ghidra.program.model.address.Address, __a2: List[ghidra.program.model.pcode.PcodeOp], __a3: int, __a4: ghidra.program.model.address.Address) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

