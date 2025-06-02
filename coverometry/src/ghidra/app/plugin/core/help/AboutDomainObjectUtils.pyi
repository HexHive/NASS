import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.util
import java.lang
import java.util


class AboutDomainObjectUtils(object):




    def __init__(self): ...



    @staticmethod
    def displayInformation(__a0: ghidra.framework.plugintool.PluginTool, __a1: ghidra.framework.model.DomainFile, __a2: java.util.Map, __a3: unicode, __a4: unicode, __a5: ghidra.util.HelpLocation) -> None: ...

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

