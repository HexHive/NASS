import ghidra.app.util.datatype.microsoft.GuidUtil
import java.lang


class GuidInfo(object):




    def __init__(self, guidString: unicode, name: unicode, type: ghidra.app.util.datatype.microsoft.GuidUtil.GuidType): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getGuidString(self) -> unicode: ...

    def getName(self) -> unicode: ...

    def getType(self) -> ghidra.app.util.datatype.microsoft.GuidUtil.GuidType: ...

    def getUniqueIdString(self) -> unicode: ...

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
    def guidString(self) -> unicode: ...

    @property
    def name(self) -> unicode: ...

    @property
    def type(self) -> ghidra.app.util.datatype.microsoft.GuidUtil.GuidType: ...

    @property
    def uniqueIdString(self) -> unicode: ...