import ghidra.app.util.bin.format.pdb2.pdbreader
import java.lang


class DelimiterState(object):




    def __init__(self, __a0: unicode, __a1: unicode): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @overload
    def out(self, __a0: bool, __a1: unicode) -> unicode: ...

    @overload
    def out(self, __a0: bool, __a1: ghidra.app.util.bin.format.pdb2.pdbreader.AbstractParsableItem) -> unicode: ...

    @overload
    def out(self, __a0: bool, __a1: object) -> unicode: ...

    def reset(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

