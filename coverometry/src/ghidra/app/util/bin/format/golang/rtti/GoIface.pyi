import ghidra.app.util.bin.format.golang.rtti
import java.lang


class GoIface(object):




    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getItab(self) -> ghidra.app.util.bin.format.golang.rtti.GoItab: ...

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
    def itab(self) -> ghidra.app.util.bin.format.golang.rtti.GoItab: ...