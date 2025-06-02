import java.lang
import java.lang.annotation


class StructureMapping(java.lang.annotation.Annotation, object):








    def annotationType(self) -> java.lang.Class: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def markupFunc(self) -> java.lang.Class: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def structureName(self) -> unicode: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

