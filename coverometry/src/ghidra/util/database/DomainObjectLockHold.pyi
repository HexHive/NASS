import ghidra.framework.model
import ghidra.util.database
import java.lang


class DomainObjectLockHold(java.lang.AutoCloseable, object):





    class DefaultHold(object, ghidra.util.database.DomainObjectLockHold):




        def __init__(self, __a0: ghidra.framework.model.DomainObject): ...



        def close(self) -> None: ...

        def equals(self, __a0: object) -> bool: ...

        @staticmethod
        def forceLock(__a0: ghidra.framework.model.DomainObject, __a1: bool, __a2: unicode) -> ghidra.util.database.DomainObjectLockHold: ...

        def getClass(self) -> java.lang.Class: ...

        def hashCode(self) -> int: ...

        @staticmethod
        def lock(__a0: ghidra.framework.model.DomainObject, __a1: unicode) -> ghidra.util.database.DomainObjectLockHold: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...







    def close(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def forceLock(__a0: ghidra.framework.model.DomainObject, __a1: bool, __a2: unicode) -> ghidra.util.database.DomainObjectLockHold: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def lock(__a0: ghidra.framework.model.DomainObject, __a1: unicode) -> ghidra.util.database.DomainObjectLockHold: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

