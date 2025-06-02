import ghidra.app.util.bin.format.golang.rtti
import ghidra.app.util.bin.format.golang.rtti.types
import java.lang
import java.util


class GoBaseType(object):
    """
    Represents the fundamental golang rtti type information.
 
     The in-memory instance will typically be part of a specialized type structure, depending
     on the 'kind' of this type.
 
     Additionally, there will be an GoUncommonType structure immediately after this type, if
     the uncommon bit is set in tflag.
 
 
     struct specialized_type { basetype_struct; (various_fields)* } struct uncommon; 
 
    """





    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getFlags(self) -> java.util.Set: ...

    def getKind(self) -> ghidra.app.util.bin.format.golang.rtti.types.GoKind: ...

    def getName(self) -> ghidra.app.util.bin.format.golang.rtti.GoName: ...

    def getNameString(self) -> unicode: ...

    def getPtrToThis(self) -> ghidra.app.util.bin.format.golang.rtti.types.GoType: ...

    def getSize(self) -> long: ...

    def getTflag(self) -> int: ...

    def hasUncommonType(self) -> bool: ...

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
    def flags(self) -> java.util.Set: ...

    @property
    def kind(self) -> ghidra.app.util.bin.format.golang.rtti.types.GoKind: ...

    @property
    def name(self) -> ghidra.app.util.bin.format.golang.rtti.GoName: ...

    @property
    def nameString(self) -> unicode: ...

    @property
    def ptrToThis(self) -> ghidra.app.util.bin.format.golang.rtti.types.GoType: ...

    @property
    def size(self) -> long: ...

    @property
    def tflag(self) -> int: ...