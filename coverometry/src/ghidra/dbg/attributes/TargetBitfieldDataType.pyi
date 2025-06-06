import com.google.gson
import ghidra.dbg.attributes
import java.lang


class TargetBitfieldDataType(ghidra.dbg.attributes.TargetDataType, object):
    UNDEFINED1: ghidra.dbg.attributes.TargetDataType = ghidra.dbg.attributes.TargetPrimitiveDataType$DefaultTargetPrimitiveDataType@17e1708c




    class DefaultTargetBitfieldDataType(object, ghidra.dbg.attributes.TargetBitfieldDataType):
        UNDEFINED1: ghidra.dbg.attributes.TargetDataType = ghidra.dbg.attributes.TargetPrimitiveDataType$DefaultTargetPrimitiveDataType@17e1708c



        def __init__(self, __a0: ghidra.dbg.attributes.TargetDataType, __a1: int, __a2: int): ...



        def equals(self, __a0: object) -> bool: ...

        def getBitLength(self) -> int: ...

        def getClass(self) -> java.lang.Class: ...

        def getFieldType(self) -> ghidra.dbg.attributes.TargetDataType: ...

        def getLeastBitPosition(self) -> int: ...

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

        @property
        def bitLength(self) -> int: ...

        @property
        def fieldType(self) -> ghidra.dbg.attributes.TargetDataType: ...

        @property
        def leastBitPosition(self) -> int: ...





    def equals(self, __a0: object) -> bool: ...

    def getBitLength(self) -> int: ...

    def getClass(self) -> java.lang.Class: ...

    def getFieldType(self) -> ghidra.dbg.attributes.TargetDataType: ...

    def getLeastBitPosition(self) -> int: ...

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

    @property
    def bitLength(self) -> int: ...

    @property
    def fieldType(self) -> ghidra.dbg.attributes.TargetDataType: ...

    @property
    def leastBitPosition(self) -> int: ...