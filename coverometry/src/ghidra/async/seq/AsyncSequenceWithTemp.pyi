import ghidra.async
import ghidra.async.seq
import java.lang
import java.util.concurrent
import java.util.concurrent.atomic
import java.util.function


class AsyncSequenceWithTemp(object):








    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def onExit(self, __a0: java.util.function.BiConsumer) -> ghidra.async.seq.AsyncSequenceWithTemp: ...

    @overload
    def then(self, __a0: ghidra.async.seq.AsyncSequenceActionConsumes) -> ghidra.async.seq.AsyncSequenceWithoutTemp: ...

    @overload
    def then(self, __a0: ghidra.async.seq.AsyncSequenceActionConsumesAndProduces, __a1: ghidra.async.TypeSpec) -> ghidra.async.seq.AsyncSequenceWithTemp: ...

    @overload
    def then(self, __a0: ghidra.async.seq.AsyncSequenceActionConsumesAndProduces, __a1: java.util.concurrent.atomic.AtomicReference) -> ghidra.async.seq.AsyncSequenceWithoutTemp: ...

    @overload
    def then(self, __a0: java.util.concurrent.Executor, __a1: ghidra.async.seq.AsyncSequenceActionConsumes) -> ghidra.async.seq.AsyncSequenceWithoutTemp: ...

    @overload
    def then(self, __a0: java.util.concurrent.Executor, __a1: ghidra.async.seq.AsyncSequenceActionConsumesAndProduces, __a2: ghidra.async.TypeSpec) -> ghidra.async.seq.AsyncSequenceWithTemp: ...

    @overload
    def then(self, __a0: java.util.concurrent.Executor, __a1: ghidra.async.seq.AsyncSequenceActionConsumesAndProduces, __a2: java.util.concurrent.atomic.AtomicReference) -> ghidra.async.seq.AsyncSequenceWithoutTemp: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

