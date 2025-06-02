import ghidra.program.model.address
import ghidra.program.model.data
import java.lang


class DWARFDataInstanceHelper(object):
    """
    Logic to test if a Data instance is replaceable with a data type.
    """





    def __init__(self, program: ghidra.program.model.listing.Program): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def isDataTypeCompatibleWithAddress(self, dataType: ghidra.program.model.data.DataType, address: ghidra.program.model.address.Address) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

