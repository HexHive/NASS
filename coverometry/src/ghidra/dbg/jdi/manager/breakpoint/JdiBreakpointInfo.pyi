import com.sun.jdi
import com.sun.jdi.request
import ghidra.dbg.jdi.manager.breakpoint
import java.lang


class JdiBreakpointInfo(object):




    @overload
    def __init__(self, __a0: com.sun.jdi.request.AccessWatchpointRequest): ...

    @overload
    def __init__(self, __a0: com.sun.jdi.request.BreakpointRequest): ...

    @overload
    def __init__(self, __a0: com.sun.jdi.request.ModificationWatchpointRequest): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getClassFilter(self) -> com.sun.jdi.ReferenceType: ...

    def getFilterPattern(self) -> unicode: ...

    def getObjectFilter(self) -> com.sun.jdi.ObjectReference: ...

    def getRequest(self) -> com.sun.jdi.request.EventRequest: ...

    def getThreadFilter(self) -> com.sun.jdi.ThreadReference: ...

    def getType(self) -> ghidra.dbg.jdi.manager.breakpoint.JdiBreakpointType: ...

    def hashCode(self) -> int: ...

    def isEnabled(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setClassFilter(self, __a0: com.sun.jdi.ReferenceType) -> None: ...

    def setEnabled(self, __a0: bool) -> None: ...

    def setFilterPattern(self, __a0: unicode) -> None: ...

    def setObjectFilter(self, __a0: com.sun.jdi.ObjectReference) -> None: ...

    def setThreadFilter(self, __a0: com.sun.jdi.ThreadReference) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def classFilter(self) -> com.sun.jdi.ReferenceType: ...

    @classFilter.setter
    def classFilter(self, value: com.sun.jdi.ReferenceType) -> None: ...

    @property
    def enabled(self) -> bool: ...

    @enabled.setter
    def enabled(self, value: bool) -> None: ...

    @property
    def filterPattern(self) -> unicode: ...

    @filterPattern.setter
    def filterPattern(self, value: unicode) -> None: ...

    @property
    def objectFilter(self) -> com.sun.jdi.ObjectReference: ...

    @objectFilter.setter
    def objectFilter(self, value: com.sun.jdi.ObjectReference) -> None: ...

    @property
    def request(self) -> com.sun.jdi.request.EventRequest: ...

    @property
    def threadFilter(self) -> com.sun.jdi.ThreadReference: ...

    @threadFilter.setter
    def threadFilter(self, value: com.sun.jdi.ThreadReference) -> None: ...

    @property
    def type(self) -> ghidra.dbg.jdi.manager.breakpoint.JdiBreakpointType: ...