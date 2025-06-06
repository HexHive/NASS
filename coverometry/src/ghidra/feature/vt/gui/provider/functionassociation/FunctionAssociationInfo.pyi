import ghidra.feature.vt.gui.provider.functionassociation
import java.lang


class FunctionAssociationInfo(object, java.lang.Comparable):




    def __init__(self, __a0: long): ...



    @overload
    def compareTo(self, __a0: ghidra.feature.vt.gui.provider.functionassociation.FunctionAssociationInfo) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getFunctionID(self) -> long: ...

    def hashCode(self) -> int: ...

    def isFilterInitialized(self) -> bool: ...

    def isInAcceptedAssociation(self) -> bool: ...

    def isInAssociation(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setFilterData(self, __a0: bool, __a1: bool) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def filterInitialized(self) -> bool: ...

    @property
    def functionID(self) -> long: ...

    @property
    def inAcceptedAssociation(self) -> bool: ...

    @property
    def inAssociation(self) -> bool: ...