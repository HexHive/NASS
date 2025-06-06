import java.lang
import java.lang.annotation


class FileSystemInfo(java.lang.annotation.Annotation, object):
    PRIORITY_DEFAULT: int = 0
    PRIORITY_HIGH: int = 10
    PRIORITY_LOW: int = -10
    PRIORITY_LOWEST: int = -2147483648







    def annotationType(self) -> java.lang.Class: ...

    def description(self) -> unicode: ...

    def equals(self, __a0: object) -> bool: ...

    def factory(self) -> java.lang.Class: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def priority(self) -> int: ...

    def toString(self) -> unicode: ...

    def type(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

