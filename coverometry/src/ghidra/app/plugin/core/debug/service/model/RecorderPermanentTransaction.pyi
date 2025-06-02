import ghidra.app.plugin.core.debug.service.model
import ghidra.framework.model
import java.lang


class RecorderPermanentTransaction(object, java.lang.AutoCloseable):




    def __init__(self, __a0: ghidra.framework.model.UndoableDomainObject, __a1: db.Transaction): ...



    def close(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def start(__a0: ghidra.framework.model.UndoableDomainObject, __a1: unicode) -> ghidra.app.plugin.core.debug.service.model.RecorderPermanentTransaction: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

