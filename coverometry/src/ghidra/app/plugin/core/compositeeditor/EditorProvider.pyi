import docking
import ghidra.app.plugin.core.compositeeditor
import ghidra.program.model.data
import java.lang


class EditorProvider(object):








    def addEditorListener(self, __a0: ghidra.app.plugin.core.compositeeditor.EditorListener) -> None: ...

    def checkForSave(self, __a0: bool) -> bool: ...

    def dispose(self) -> None: ...

    def domainObjectRestored(self, __a0: ghidra.program.model.data.DataTypeManagerDomainObject) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getComponentProvider(self) -> docking.ComponentProvider: ...

    def getDataTypeManager(self) -> ghidra.program.model.data.DataTypeManager: ...

    def getDtPath(self) -> ghidra.program.model.data.DataTypePath: ...

    def getName(self) -> unicode: ...

    def hashCode(self) -> int: ...

    def isEditing(self, __a0: ghidra.program.model.data.DataTypePath) -> bool: ...

    def needsSave(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def show(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def componentProvider(self) -> docking.ComponentProvider: ...

    @property
    def dataTypeManager(self) -> ghidra.program.model.data.DataTypeManager: ...

    @property
    def dtPath(self) -> ghidra.program.model.data.DataTypePath: ...

    @property
    def name(self) -> unicode: ...