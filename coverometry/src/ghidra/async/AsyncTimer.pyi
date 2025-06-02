import ghidra.async
import java.lang
import java.util.concurrent
import java.util.function


class AsyncTimer(object):
    DEFAULT_TIMER: ghidra.async.AsyncTimer = ghidra.async.AsyncTimer@1374d2a8




    class Mark(object):








        def after(self, __a0: long) -> java.util.concurrent.CompletableFuture: ...

        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def hashCode(self) -> int: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def timeOut(self, __a0: java.util.concurrent.CompletableFuture, __a1: long, __a2: java.util.function.Supplier) -> java.util.concurrent.CompletableFuture: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...



    def __init__(self): ...



    def atSystemTime(self, __a0: long) -> java.util.concurrent.CompletableFuture: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def mark(self) -> ghidra.async.AsyncTimer.Mark: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

