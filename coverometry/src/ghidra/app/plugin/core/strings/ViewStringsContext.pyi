from typing import List
import docking
import ghidra.app.context
import ghidra.program.model.listing
import java.awt
import java.awt.event
import java.lang
import java.util.function


class ViewStringsContext(docking.DefaultActionContext, ghidra.app.context.DataLocationListContext):








    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getComponentProvider(self) -> docking.ComponentProvider: ...

    def getContextObject(self) -> object: ...

    def getCount(self) -> int: ...

    @overload
    def getDataLocationList(self) -> List[object]: ...

    @overload
    def getDataLocationList(self, __a0: java.util.function.Predicate) -> List[object]: ...

    def getEventClickModifiers(self) -> int: ...

    def getMouseEvent(self) -> java.awt.event.MouseEvent: ...

    def getProgram(self) -> ghidra.program.model.listing.Program: ...

    def getSourceComponent(self) -> java.awt.Component: ...

    def getSourceObject(self) -> object: ...

    def hasAnyEventClickModifiers(self, __a0: int) -> bool: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setContextObject(self, __a0: object) -> docking.ActionContext: ...

    def setEventClickModifiers(self, __a0: int) -> None: ...

    def setMouseEvent(self, __a0: java.awt.event.MouseEvent) -> docking.ActionContext: ...

    def setSourceObject(self, __a0: object) -> docking.ActionContext: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def count(self) -> int: ...

    @property
    def dataLocationList(self) -> List[object]: ...

    @property
    def program(self) -> ghidra.program.model.listing.Program: ...