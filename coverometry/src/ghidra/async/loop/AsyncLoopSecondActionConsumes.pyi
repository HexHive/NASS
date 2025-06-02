import java.lang
import java.util.function


class AsyncLoopSecondActionConsumes(java.util.function.BiConsumer, object):








    def accept(self, __a0: object, __a1: object) -> None: ...

    def andThen(self, __a0: java.util.function.BiConsumer) -> java.util.function.BiConsumer: ...

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

