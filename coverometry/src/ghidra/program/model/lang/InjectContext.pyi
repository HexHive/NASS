import ghidra.program.model.pcode
import java.lang


class InjectContext(object):
    baseAddr: ghidra.program.model.address.Address
    callAddr: ghidra.program.model.address.Address
    inputlist: java.util.ArrayList
    language: ghidra.app.plugin.processors.sleigh.SleighLanguage
    nextAddr: ghidra.program.model.address.Address
    output: java.util.ArrayList
    refAddr: ghidra.program.model.address.Address



    def __init__(self): ...



    def decode(self, decoder: ghidra.program.model.pcode.Decoder) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

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

