import ghidra.app.util.bin
import ghidra.javaclass.format.constantpool
import java.lang


class ConstantPoolFactory(object):




    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def get(__a0: ghidra.app.util.bin.BinaryReader) -> ghidra.javaclass.format.constantpool.AbstractConstantPoolInfoJava: ...

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

