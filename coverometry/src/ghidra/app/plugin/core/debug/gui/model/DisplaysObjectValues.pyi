import ghidra.trace.model.target
import java.lang


class DisplaysObjectValues(object):








    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getEdgeDisplay(self, __a0: ghidra.trace.model.target.TraceObjectValue) -> unicode: ...

    def getEdgeHtmlDisplay(self, __a0: ghidra.trace.model.target.TraceObjectValue) -> unicode: ...

    def getEdgeToolTip(self, __a0: ghidra.trace.model.target.TraceObjectValue) -> unicode: ...

    def getNullDisplay(self) -> unicode: ...

    def getObjectDisplay(self, __a0: ghidra.trace.model.target.TraceObjectValue) -> unicode: ...

    def getObjectLinkDisplay(self, __a0: ghidra.trace.model.target.TraceObjectValue) -> unicode: ...

    def getObjectLinkToolTip(self, __a0: ghidra.trace.model.target.TraceObjectValue) -> unicode: ...

    def getObjectToolTip(self, __a0: ghidra.trace.model.target.TraceObjectValue) -> unicode: ...

    def getObjectType(self, __a0: ghidra.trace.model.target.TraceObjectValue) -> unicode: ...

    def getPrimitiveEdgeToolTip(self, __a0: ghidra.trace.model.target.TraceObjectValue) -> unicode: ...

    def getPrimitiveEdgeType(self, __a0: ghidra.trace.model.target.TraceObjectValue) -> unicode: ...

    def getPrimitiveValueDisplay(self, __a0: object) -> unicode: ...

    def getRawObjectDisplay(self, __a0: ghidra.trace.model.target.TraceObjectValue) -> unicode: ...

    def getSnap(self) -> long: ...

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
    def nullDisplay(self) -> unicode: ...

    @property
    def snap(self) -> long: ...