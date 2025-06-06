import ghidra.app.plugin.core.debug.gui.pcode
import ghidra.program.model.pcode
import java.lang


class OpPcodeRow(object, ghidra.app.plugin.core.debug.gui.pcode.PcodeRow):




    def __init__(self, __a0: ghidra.program.model.lang.Language, __a1: ghidra.program.model.pcode.PcodeOp, __a2: bool, __a3: unicode, __a4: unicode): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getCode(self) -> unicode: ...

    def getLabel(self) -> unicode: ...

    def getOp(self) -> ghidra.program.model.pcode.PcodeOp: ...

    def getSequence(self) -> int: ...

    def hashCode(self) -> int: ...

    def isNext(self) -> bool: ...

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
    def code(self) -> unicode: ...

    @property
    def label(self) -> unicode: ...

    @property
    def next(self) -> bool: ...

    @property
    def op(self) -> ghidra.program.model.pcode.PcodeOp: ...

    @property
    def sequence(self) -> int: ...