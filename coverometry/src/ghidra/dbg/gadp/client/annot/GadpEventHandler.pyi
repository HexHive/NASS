import ghidra.dbg.gadp.protocol
import java.lang
import java.lang.annotation


class GadpEventHandler(java.lang.annotation.Annotation, object):








    def annotationType(self) -> java.lang.Class: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    def value(self) -> ghidra.dbg.gadp.protocol.Gadp.EventNotification.EvtCase: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

