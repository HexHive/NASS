import ghidra.app.plugin.exceptionhandlers.gcc.structures.ehFrame
import ghidra.program.model.address
import java.lang


class CieSource(object):
    """
    Provides GCC exception handling model classes the means to obtain a Common Information Entry
     (CIE) object for a given address.
    """









    def equals(self, __a0: object) -> bool: ...

    def getCie(self, currAddress: ghidra.program.model.address.Address) -> ghidra.app.plugin.exceptionhandlers.gcc.structures.ehFrame.Cie:
        """
        For the provided address, return a Common Information Entry (CIE)
        @param currAddress the address with the CIE
        @return the Cie at <code>currAddress</code>
        @throws MemoryAccessException if memory for the CIE couldn't be read
        @throws ExceptionHandlerFrameException if a problem was encountered
        """
        ...

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

