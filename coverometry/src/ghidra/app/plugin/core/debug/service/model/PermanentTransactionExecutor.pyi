import java.lang
import java.util.concurrent


class PermanentTransactionExecutor(object):




    def __init__(self, __a0: ghidra.framework.model.UndoableDomainObject, __a1: unicode, __a2: int, __a3: int): ...



    def equals(self, __a0: object) -> bool: ...

    def execute(self, __a0: unicode, __a1: java.lang.Runnable, __a2: object) -> java.util.concurrent.CompletableFuture: ...

    def flush(self) -> java.util.concurrent.CompletableFuture: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def shutdownNow(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

