from typing import List
import ghidra.app.util.bin.format.golang.rtti.types
import java.lang
import java.util


class GoKind(java.lang.Enum):
    Array: ghidra.app.util.bin.format.golang.rtti.types.GoKind = Array
    Bool: ghidra.app.util.bin.format.golang.rtti.types.GoKind = Bool
    Chan: ghidra.app.util.bin.format.golang.rtti.types.GoKind = Chan
    Complex128: ghidra.app.util.bin.format.golang.rtti.types.GoKind = Complex128
    Complex64: ghidra.app.util.bin.format.golang.rtti.types.GoKind = Complex64
    DIRECT_IFACE: int = 32
    Float32: ghidra.app.util.bin.format.golang.rtti.types.GoKind = Float32
    Float64: ghidra.app.util.bin.format.golang.rtti.types.GoKind = Float64
    Func: ghidra.app.util.bin.format.golang.rtti.types.GoKind = Func
    GC_PROG: int = 64
    Int: ghidra.app.util.bin.format.golang.rtti.types.GoKind = Int
    Int16: ghidra.app.util.bin.format.golang.rtti.types.GoKind = Int16
    Int32: ghidra.app.util.bin.format.golang.rtti.types.GoKind = Int32
    Int64: ghidra.app.util.bin.format.golang.rtti.types.GoKind = Int64
    Int8: ghidra.app.util.bin.format.golang.rtti.types.GoKind = Int8
    Interface: ghidra.app.util.bin.format.golang.rtti.types.GoKind = Interface
    KIND_MASK: int = 31
    Map: ghidra.app.util.bin.format.golang.rtti.types.GoKind = Map
    Pointer: ghidra.app.util.bin.format.golang.rtti.types.GoKind = Pointer
    Slice: ghidra.app.util.bin.format.golang.rtti.types.GoKind = Slice
    String: ghidra.app.util.bin.format.golang.rtti.types.GoKind = String
    Struct: ghidra.app.util.bin.format.golang.rtti.types.GoKind = Struct
    Uint: ghidra.app.util.bin.format.golang.rtti.types.GoKind = Uint
    Uint16: ghidra.app.util.bin.format.golang.rtti.types.GoKind = Uint16
    Uint32: ghidra.app.util.bin.format.golang.rtti.types.GoKind = Uint32
    Uint64: ghidra.app.util.bin.format.golang.rtti.types.GoKind = Uint64
    Uint8: ghidra.app.util.bin.format.golang.rtti.types.GoKind = Uint8
    Uintptr: ghidra.app.util.bin.format.golang.rtti.types.GoKind = Uintptr
    UnsafePointer: ghidra.app.util.bin.format.golang.rtti.types.GoKind = UnsafePointer
    invalid: ghidra.app.util.bin.format.golang.rtti.types.GoKind = invalid







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

    @staticmethod
    def parseByte(__a0: int) -> ghidra.app.util.bin.format.golang.rtti.types.GoKind: ...

    def toString(self) -> unicode: ...

    @overload
    @staticmethod
    def valueOf(__a0: unicode) -> ghidra.app.util.bin.format.golang.rtti.types.GoKind: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.app.util.bin.format.golang.rtti.types.GoKind]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

