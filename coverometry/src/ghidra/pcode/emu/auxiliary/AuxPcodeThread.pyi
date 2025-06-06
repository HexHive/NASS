import ghidra.app.plugin.processors.sleigh
import ghidra.pcode.emu
import ghidra.pcode.exec
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.listing
import java.lang


class AuxPcodeThread(ghidra.pcode.emu.ModifiedPcodeThread):




    def __init__(self, __a0: unicode, __a1: ghidra.pcode.emu.auxiliary.AuxPcodeEmulator): ...



    def assignContext(self, __a0: ghidra.program.model.lang.RegisterValue) -> None: ...

    def clearAllInjects(self) -> None: ...

    def clearInject(self, __a0: ghidra.program.model.address.Address) -> None: ...

    def dropInstruction(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def executeInstruction(self) -> None: ...

    def finishInstruction(self) -> None: ...

    def getArithmetic(self) -> ghidra.pcode.exec.PcodeArithmetic: ...

    def getClass(self) -> java.lang.Class: ...

    def getContext(self) -> ghidra.program.model.lang.RegisterValue: ...

    def getCounter(self) -> ghidra.program.model.address.Address: ...

    def getExecutor(self) -> ghidra.pcode.exec.PcodeExecutor: ...

    def getFrame(self) -> ghidra.pcode.exec.PcodeFrame: ...

    def getInstruction(self) -> ghidra.program.model.listing.Instruction: ...

    def getLanguage(self) -> ghidra.app.plugin.processors.sleigh.SleighLanguage: ...

    def getMachine(self) -> ghidra.pcode.emu.PcodeMachine: ...

    def getName(self) -> unicode: ...

    def getState(self) -> ghidra.pcode.emu.ThreadPcodeExecutorState: ...

    def getUseropLibrary(self) -> ghidra.pcode.exec.PcodeUseropLibrary: ...

    def hashCode(self) -> int: ...

    def inject(self, __a0: ghidra.program.model.address.Address, __a1: unicode) -> None: ...

    def isSuspended(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def overrideContext(self, __a0: ghidra.program.model.lang.RegisterValue) -> None: ...

    def overrideContextWithDefault(self) -> None: ...

    def overrideCounter(self, __a0: ghidra.program.model.address.Address) -> None: ...

    def reInitialize(self) -> None: ...

    def run(self) -> None: ...

    def setCounter(self, __a0: ghidra.program.model.address.Address) -> None: ...

    def setSuspended(self, __a0: bool) -> None: ...

    def skipInstruction(self) -> None: ...

    def skipPcodeOp(self) -> None: ...

    @overload
    def stepInstruction(self) -> None: ...

    @overload
    def stepInstruction(self, __a0: long) -> None: ...

    def stepPatch(self, __a0: unicode) -> None: ...

    @overload
    def stepPcodeOp(self) -> None: ...

    @overload
    def stepPcodeOp(self, __a0: long) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def machine(self) -> ghidra.pcode.emu.auxiliary.AuxPcodeEmulator: ...