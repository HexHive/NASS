import docking
import ghidra.app.context
import ghidra.program.model.listing
import ghidra.program.model.symbol
import java.awt
import java.awt.event
import java.lang


class ProgramSymbolActionContext(ghidra.app.context.ProgramActionContext):




    def __init__(self, __a0: docking.ComponentProvider, __a1: ghidra.program.model.listing.Program, __a2: List[object], __a3: java.awt.Component): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getComponentProvider(self) -> docking.ComponentProvider: ...

    def getContextObject(self) -> object: ...

    def getEventClickModifiers(self) -> int: ...

    def getFirstSymbol(self) -> ghidra.program.model.symbol.Symbol: ...

    def getMouseEvent(self) -> java.awt.event.MouseEvent: ...

    def getProgram(self) -> ghidra.program.model.listing.Program: ...

    def getSourceComponent(self) -> java.awt.Component: ...

    def getSourceObject(self) -> object: ...

    def getSymbolCount(self) -> int: ...

    def getSymbols(self) -> java.lang.Iterable: ...

    def hasAnyEventClickModifiers(self, modifiersMask: int) -> bool: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setContextObject(self, contextObject: object) -> docking.DefaultActionContext: ...

    def setEventClickModifiers(self, modifiers: int) -> None: ...

    def setMouseEvent(self, e: java.awt.event.MouseEvent) -> docking.DefaultActionContext: ...

    def setSourceObject(self, sourceObject: object) -> docking.DefaultActionContext: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def firstSymbol(self) -> ghidra.program.model.symbol.Symbol: ...

    @property
    def symbolCount(self) -> int: ...

    @property
    def symbols(self) -> java.lang.Iterable: ...