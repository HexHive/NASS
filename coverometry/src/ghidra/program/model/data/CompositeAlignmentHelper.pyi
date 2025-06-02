import ghidra.program.model.data
import java.lang


class CompositeAlignmentHelper(object):




    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def getAlignment(dataOrganization: ghidra.program.model.data.DataOrganization, composite: ghidra.program.model.data.CompositeInternal) -> int: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getPackedAlignment(dataOrganization: ghidra.program.model.data.DataOrganization, packingValue: int, component: ghidra.program.model.data.DataTypeComponent) -> int: ...

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

