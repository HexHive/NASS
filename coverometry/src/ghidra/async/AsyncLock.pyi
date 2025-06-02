import ghidra.async
import ghidra.async.seq
import java.lang
import java.util.concurrent
import java.util.concurrent.atomic


class AsyncLock(object):





    class Hold(object):








        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def hashCode(self) -> int: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def release(self) -> None: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...



    @overload
    def __init__(self): ...

    @overload
    def __init__(self, __a0: unicode): ...



    def acquire(self, __a0: ghidra.async.AsyncLock.Hold) -> java.util.concurrent.CompletableFuture: ...

    def dispose(self, __a0: java.lang.Throwable) -> None: ...

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

    @overload
    def with(self, __a0: ghidra.async.TypeSpec, __a1: ghidra.async.AsyncLock.Hold) -> ghidra.async.seq.AsyncSequenceWithTemp: ...

    @overload
    def with(self, __a0: ghidra.async.TypeSpec, __a1: ghidra.async.AsyncLock.Hold, __a2: java.util.concurrent.atomic.AtomicReference) -> ghidra.async.seq.AsyncSequenceWithoutTemp: ...

