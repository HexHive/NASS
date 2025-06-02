import ghidra.async
import ghidra.framework.options
import ghidra.framework.plugintool
import java.lang


class AsyncConfigFieldCodec(object):





    class BooleanAsyncConfigFieldCodec(ghidra.async.AsyncConfigFieldCodec.GenericAsyncConfigFieldCodec):




        def __init__(self): ...



        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def hashCode(self) -> int: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        @overload
        def read(self, __a0: ghidra.framework.options.SaveState, __a1: unicode, __a2: ghidra.async.AsyncReference) -> ghidra.async.AsyncReference: ...

        @overload
        def read(self, __a0: ghidra.framework.options.SaveState, __a1: unicode, __a2: object) -> object: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...

        @overload
        def write(self, __a0: ghidra.framework.options.SaveState, __a1: unicode, __a2: ghidra.async.AsyncReference) -> None: ...

        @overload
        def write(self, __a0: ghidra.framework.options.SaveState, __a1: unicode, __a2: object) -> None: ...






    class GenericAsyncConfigFieldCodec(object, ghidra.framework.plugintool.AutoConfigState.ConfigFieldCodec):




        def __init__(self, __a0: ghidra.framework.plugintool.AutoConfigState.ConfigFieldCodec): ...



        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def hashCode(self) -> int: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        @overload
        def read(self, __a0: ghidra.framework.options.SaveState, __a1: unicode, __a2: ghidra.async.AsyncReference) -> ghidra.async.AsyncReference: ...

        @overload
        def read(self, __a0: ghidra.framework.options.SaveState, __a1: unicode, __a2: object) -> object: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...

        @overload
        def write(self, __a0: ghidra.framework.options.SaveState, __a1: unicode, __a2: ghidra.async.AsyncReference) -> None: ...

        @overload
        def write(self, __a0: ghidra.framework.options.SaveState, __a1: unicode, __a2: object) -> None: ...







    def equals(self, __a0: object) -> bool: ...

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

