import ghidra.program.model.address
import ghidra.trace.model
import ghidra.trace.model.modules
import java.lang


class SectionRow(object):




    def __init__(self, __a0: ghidra.trace.model.modules.TraceSection): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getEnd(self) -> ghidra.program.model.address.Address: ...

    def getLength(self) -> long: ...

    def getModule(self) -> ghidra.trace.model.modules.TraceModule: ...

    def getModuleName(self) -> unicode: ...

    def getName(self) -> unicode: ...

    def getRange(self) -> ghidra.program.model.address.AddressRange: ...

    def getSection(self) -> ghidra.trace.model.modules.TraceSection: ...

    def getStart(self) -> ghidra.program.model.address.Address: ...

    def getTraceLocation(self) -> ghidra.trace.model.TraceLocation: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setName(self, __a0: unicode) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def end(self) -> ghidra.program.model.address.Address: ...

    @property
    def length(self) -> long: ...

    @property
    def module(self) -> ghidra.trace.model.modules.TraceModule: ...

    @property
    def moduleName(self) -> unicode: ...

    @property
    def name(self) -> unicode: ...

    @name.setter
    def name(self, value: unicode) -> None: ...

    @property
    def range(self) -> ghidra.program.model.address.AddressRange: ...

    @property
    def section(self) -> ghidra.trace.model.modules.TraceSection: ...

    @property
    def start(self) -> ghidra.program.model.address.Address: ...

    @property
    def traceLocation(self) -> ghidra.trace.model.TraceLocation: ...