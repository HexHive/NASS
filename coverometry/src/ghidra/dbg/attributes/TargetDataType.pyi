import com.google.gson
import java.lang


class TargetDataType(object):
    UNDEFINED1: ghidra.dbg.attributes.TargetDataType = ghidra.dbg.attributes.TargetPrimitiveDataType$DefaultTargetPrimitiveDataType@17e1708c







    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toJson(self) -> com.google.gson.JsonElement: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

