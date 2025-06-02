from typing import List
import java.lang
import java.lang.annotation


class HelpInfo(java.lang.annotation.Annotation, object):








    def anchor(self) -> unicode: ...

    def annotationType(self) -> java.lang.Class: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    def topic(self) -> List[unicode]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

