import ghidra.app.plugin.exceptionhandlers.gcc.sections
import ghidra.app.plugin.exceptionhandlers.gcc.structures.ehFrame
import ghidra.program.model.address
import java.lang


class AbstractFrameSection(object, ghidra.app.plugin.exceptionhandlers.gcc.sections.CieSource):
    """
    Extend this class to parse the call frame information exception handling structures within a 
     particular frame memory section.
    """









    def equals(self, __a0: object) -> bool: ...

    def getCie(self, __a0: ghidra.program.model.address.Address) -> ghidra.app.plugin.exceptionhandlers.gcc.structures.ehFrame.Cie: ...

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

