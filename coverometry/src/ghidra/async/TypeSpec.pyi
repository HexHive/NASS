import ghidra.async
import java.lang
import java.util.concurrent


class TypeSpec(object):
    BOOLEAN: ghidra.async.TypeSpec = ghidra.async.TypeSpec$1@127e3bbb
    BYTE: ghidra.async.TypeSpec = ghidra.async.TypeSpec$1@127e3bbb
    BYTE_ARRAY: ghidra.async.TypeSpec = ghidra.async.TypeSpec$1@127e3bbb
    CHAR: ghidra.async.TypeSpec = ghidra.async.TypeSpec$1@127e3bbb
    INT: ghidra.async.TypeSpec = ghidra.async.TypeSpec$1@127e3bbb
    LONG: ghidra.async.TypeSpec = ghidra.async.TypeSpec$1@127e3bbb
    OBJECT: ghidra.async.TypeSpec = ghidra.async.TypeSpec$1@127e3bbb
    RAW: ghidra.async.TypeSpec = ghidra.async.TypeSpec$1@127e3bbb
    SHORT: ghidra.async.TypeSpec = ghidra.async.TypeSpec$1@127e3bbb
    STRING: ghidra.async.TypeSpec = ghidra.async.TypeSpec$1@127e3bbb
    VOID: ghidra.async.TypeSpec = ghidra.async.TypeSpec$1@127e3bbb




    class FuncArity1(object):








        def equals(self, __a0: object) -> bool: ...

        def func(self, __a0: object) -> object: ...

        def getClass(self) -> java.lang.Class: ...

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






    class FuncArity2(object):








        def equals(self, __a0: object) -> bool: ...

        def func(self, __a0: object, __a1: object) -> object: ...

        def getClass(self) -> java.lang.Class: ...

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






    class FuncArity3(object):








        def equals(self, __a0: object) -> bool: ...

        def func(self, __a0: object, __a1: object, __a2: object) -> object: ...

        def getClass(self) -> java.lang.Class: ...

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






    class FuncArity4(object):








        def equals(self, __a0: object) -> bool: ...

        def func(self, __a0: object, __a1: object, __a2: object, __a3: object) -> object: ...

        def getClass(self) -> java.lang.Class: ...

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






    class FuncArity0(object):








        def equals(self, __a0: object) -> bool: ...

        def func(self) -> object: ...

        def getClass(self) -> java.lang.Class: ...

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







    @staticmethod
    def auto() -> ghidra.async.TypeSpec: ...

    @staticmethod
    def cls(__a0: java.lang.Class) -> ghidra.async.TypeSpec: ...

    @overload
    def col(self) -> ghidra.async.TypeSpec: ...

    @overload
    def col(self, __a0: java.lang.Class) -> ghidra.async.TypeSpec: ...

    def equals(self, __a0: object) -> bool: ...

    def ext(self) -> ghidra.async.TypeSpec: ...

    @staticmethod
    def from(__a0: java.util.concurrent.Future) -> ghidra.async.TypeSpec: ...

    @overload
    @staticmethod
    def future(__a0: ghidra.async.TypeSpec.FuncArity0) -> ghidra.async.TypeSpec: ...

    @overload
    @staticmethod
    def future(__a0: ghidra.async.TypeSpec.FuncArity1) -> ghidra.async.TypeSpec: ...

    @overload
    @staticmethod
    def future(__a0: ghidra.async.TypeSpec.FuncArity2) -> ghidra.async.TypeSpec: ...

    @overload
    @staticmethod
    def future(__a0: ghidra.async.TypeSpec.FuncArity3) -> ghidra.async.TypeSpec: ...

    @overload
    @staticmethod
    def future(__a0: ghidra.async.TypeSpec.FuncArity4) -> ghidra.async.TypeSpec: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def list(self) -> ghidra.async.TypeSpec: ...

    @staticmethod
    def map(__a0: java.lang.Class, __a1: java.lang.Class) -> ghidra.async.TypeSpec: ...

    @overload
    def mappedBy(self, __a0: ghidra.async.TypeSpec) -> ghidra.async.TypeSpec: ...

    @overload
    def mappedBy(self, __a0: java.lang.Class) -> ghidra.async.TypeSpec: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def obj(__a0: object) -> ghidra.async.TypeSpec: ...

    @staticmethod
    def pair(__a0: ghidra.async.TypeSpec, __a1: ghidra.async.TypeSpec) -> ghidra.async.TypeSpec: ...

    def set(self) -> ghidra.async.TypeSpec: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

