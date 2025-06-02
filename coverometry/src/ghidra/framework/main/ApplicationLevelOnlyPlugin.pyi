import ghidra.framework.main
import java.lang


class ApplicationLevelOnlyPlugin(ghidra.framework.main.ApplicationLevelPlugin, object):
    """
    Marker interface to indicate this plugin is application-level tools only (see
     ApplicationLevelPlugin).
    """









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

