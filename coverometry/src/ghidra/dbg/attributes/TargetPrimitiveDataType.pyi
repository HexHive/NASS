from typing import List
import com.google.gson
import ghidra.dbg.attributes
import java.lang
import java.util


class TargetPrimitiveDataType(ghidra.dbg.attributes.TargetDataType, object):
    UNDEFINED1: ghidra.dbg.attributes.TargetDataType = ghidra.dbg.attributes.TargetPrimitiveDataType$DefaultTargetPrimitiveDataType@17e1708c
    VOID: ghidra.dbg.attributes.TargetDataType = ghidra.dbg.attributes.TargetPrimitiveDataType$DefaultTargetPrimitiveDataType@1ab37188




    class PrimitiveKind(java.lang.Enum):
        COMPLEX: ghidra.dbg.attributes.TargetPrimitiveDataType.PrimitiveKind = COMPLEX
        FLOAT: ghidra.dbg.attributes.TargetPrimitiveDataType.PrimitiveKind = FLOAT
        SINT: ghidra.dbg.attributes.TargetPrimitiveDataType.PrimitiveKind = SINT
        UINT: ghidra.dbg.attributes.TargetPrimitiveDataType.PrimitiveKind = UINT
        UNDEFINED: ghidra.dbg.attributes.TargetPrimitiveDataType.PrimitiveKind = UNDEFINED
        VOID: ghidra.dbg.attributes.TargetPrimitiveDataType.PrimitiveKind = VOID







        @overload
        def compareTo(self, __a0: java.lang.Enum) -> int: ...

        @overload
        def compareTo(self, __a0: object) -> int: ...

        def describeConstable(self) -> java.util.Optional: ...

        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def getDeclaringClass(self) -> java.lang.Class: ...

        def hashCode(self) -> int: ...

        def name(self) -> unicode: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def ordinal(self) -> int: ...

        def toString(self) -> unicode: ...

        @overload
        @staticmethod
        def valueOf(__a0: unicode) -> ghidra.dbg.attributes.TargetPrimitiveDataType.PrimitiveKind: ...

        @overload
        @staticmethod
        def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

        @staticmethod
        def values() -> List[ghidra.dbg.attributes.TargetPrimitiveDataType.PrimitiveKind]: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...






    class DefaultTargetPrimitiveDataType(object, ghidra.dbg.attributes.TargetPrimitiveDataType):
        UNDEFINED1: ghidra.dbg.attributes.TargetDataType = ghidra.dbg.attributes.TargetPrimitiveDataType$DefaultTargetPrimitiveDataType@17e1708c
        VOID: ghidra.dbg.attributes.TargetDataType = ghidra.dbg.attributes.TargetPrimitiveDataType$DefaultTargetPrimitiveDataType@1ab37188



        def __init__(self, __a0: ghidra.dbg.attributes.TargetPrimitiveDataType.PrimitiveKind, __a1: int): ...



        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def getKind(self) -> ghidra.dbg.attributes.TargetPrimitiveDataType.PrimitiveKind: ...

        def getLength(self) -> int: ...

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
        def kind(self) -> ghidra.dbg.attributes.TargetPrimitiveDataType.PrimitiveKind: ...

        @property
        def length(self) -> int: ...





    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getKind(self) -> ghidra.dbg.attributes.TargetPrimitiveDataType.PrimitiveKind: ...

    def getLength(self) -> int: ...

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
    def kind(self) -> ghidra.dbg.attributes.TargetPrimitiveDataType.PrimitiveKind: ...

    @property
    def length(self) -> int: ...