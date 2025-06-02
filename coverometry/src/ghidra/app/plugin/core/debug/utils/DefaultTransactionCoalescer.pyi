import ghidra.app.plugin.core.debug.utils
import java.lang


class DefaultTransactionCoalescer(object, ghidra.app.plugin.core.debug.utils.TransactionCoalescer):





    class DefaultCoalescedTx(object, ghidra.app.plugin.core.debug.utils.TransactionCoalescer.CoalescedTx):








        def close(self) -> None: ...

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



    def __init__(self, __a0: ghidra.framework.model.UndoableDomainObject, __a1: ghidra.app.plugin.core.debug.utils.TransactionCoalescer.TxFactory, __a2: int): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def start(self, __a0: unicode) -> ghidra.app.plugin.core.debug.utils.DefaultTransactionCoalescer.DefaultCoalescedTx: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

