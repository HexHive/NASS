import ghidra.framework.options
import java.lang


class FGLayoutOptions(object):
    OWNER: unicode = u'FunctionGraphPlugin'







    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def loadOptions(self, __a0: ghidra.framework.options.Options) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def optionChangeRequiresRelayout(self, __a0: unicode) -> bool: ...

    def registerOptions(self, __a0: ghidra.framework.options.Options) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

