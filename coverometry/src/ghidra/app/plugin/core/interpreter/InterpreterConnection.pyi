from typing import List
import java.lang
import javax.swing


class InterpreterConnection(object):








    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @overload
    def getCompletions(self, __a0: unicode) -> List[object]: ...

    @overload
    def getCompletions(self, __a0: unicode, __a1: int) -> List[object]: ...

    def getIcon(self) -> javax.swing.Icon: ...

    def getTitle(self) -> unicode: ...

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

    @property
    def icon(self) -> javax.swing.Icon: ...

    @property
    def title(self) -> unicode: ...