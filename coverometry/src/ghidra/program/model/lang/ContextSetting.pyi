from typing import List
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.pcode
import ghidra.xml
import java.lang


class ContextSetting(object):
    """
    Class for context configuration information as
     part of the compiler configuration (CompilerSpec)
    """





    def __init__(self, register: ghidra.program.model.lang.Register, value: long, startAddr: ghidra.program.model.address.Address, endAddr: ghidra.program.model.address.Address): ...



    def encode(self, encoder: ghidra.program.model.pcode.Encoder) -> None: ...

    @staticmethod
    def encodeContextData(__a0: ghidra.program.model.pcode.Encoder, __a1: List[object]) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getEndAddress(self) -> ghidra.program.model.address.Address: ...

    def getRegister(self) -> ghidra.program.model.lang.Register: ...

    def getStartAddress(self) -> ghidra.program.model.address.Address: ...

    def getValue(self) -> long: ...

    def hashCode(self) -> int: ...

    def isEquivalent(self, obj: ghidra.program.model.lang.ContextSetting) -> bool:
        """
        Determine if this ContextSetting is equivalent to another specified instance
        @param obj is the other instance
        @return true if they are equivalent
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def parseContextData(__a0: List[object], __a1: ghidra.xml.XmlPullParser, __a2: ghidra.program.model.lang.CompilerSpec) -> None: ...

    @staticmethod
    def parseContextSet(__a0: List[object], __a1: ghidra.xml.XmlPullParser, __a2: ghidra.program.model.lang.CompilerSpec) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def endAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def register(self) -> ghidra.program.model.lang.Register: ...

    @property
    def startAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def value(self) -> long: ...