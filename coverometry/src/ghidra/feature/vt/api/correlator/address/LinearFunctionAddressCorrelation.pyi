import ghidra.program.model.address
import ghidra.program.util
import ghidra.util.task
import java.lang


class LinearFunctionAddressCorrelation(object, ghidra.program.util.AddressCorrelation):
    NAME: unicode = u'LinearFunctionAddressCorrelation'







    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getCorrelatedDestinationRange(self, __a0: ghidra.program.model.address.Address, __a1: ghidra.util.task.TaskMonitor) -> ghidra.program.model.address.AddressRange: ...

    def getName(self) -> unicode: ...

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
    def name(self) -> unicode: ...