import java.lang


class ApplicationLevelPlugin(object):
    """
    Marker that signals the implementing plugin can be added to the system at the application level.
 
     Some applications have only a single tool while other applications may have multiple tools, with
     a top-level tool that manages other sub-tools.  A plugin implementing this interface can be used
     in any of these tools.
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

