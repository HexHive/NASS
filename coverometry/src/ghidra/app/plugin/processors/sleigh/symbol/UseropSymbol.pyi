import ghidra.app.plugin.processors.sleigh
import ghidra.app.plugin.processors.sleigh.symbol
import ghidra.xml
import java.lang


class UseropSymbol(ghidra.app.plugin.processors.sleigh.symbol.Symbol):
    """
    A user-defined pcode operation (PcodeOp)
     This is implemented as a name and a unique id which is passed
     as the first parameter to a PcodeOp with the opcode = "CALLOTHER".
    """





    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getId(self) -> int: ...

    def getIndex(self) -> int: ...

    def getName(self) -> unicode: ...

    def getScopeId(self) -> int: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def restoreHeaderXml(self, parser: ghidra.xml.XmlPullParser) -> None: ...

    def restoreXml(self, parser: ghidra.xml.XmlPullParser, sleigh: ghidra.app.plugin.processors.sleigh.SleighLanguage) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def index(self) -> int: ...