from typing import List
import ghidra.app.util.pcode
import ghidra.program.model.address
import ghidra.program.model.lang
import java.lang


class AbstractPcodeFormatter(object, ghidra.app.util.pcode.PcodeFormatter):
    """
    An abstract p-code formatter which can take a list of p-code ops or op templates and consistently
     format them. The general pattern is to extend this class and specify another class which extends
     an AbstractAppender. In most cases, it is only necessary to override
     #formatOpTemplate(Appender, OpTpl). Otherwise, most formatting logic is implemented by
     the appender.
    """





    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    @overload
    def formatOps(self, __a0: ghidra.program.model.lang.Language, __a1: List[object]) -> object: ...

    @overload
    def formatOps(self, __a0: ghidra.program.model.lang.Language, __a1: ghidra.program.model.address.AddressFactory, __a2: List[object]) -> object: ...

    def formatTemplates(self, __a0: ghidra.program.model.lang.Language, __a1: List[object]) -> object: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getPcodeOpTemplates(__a0: ghidra.program.model.address.AddressFactory, __a1: List[object]) -> List[object]: ...

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

