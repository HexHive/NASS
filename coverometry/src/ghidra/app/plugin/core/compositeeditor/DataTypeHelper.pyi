import ghidra.app.plugin.core.compositeeditor
import ghidra.app.services
import ghidra.program.model.data
import java.lang


class DataTypeHelper(object):




    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def getBaseType(__a0: ghidra.program.model.data.DataType) -> ghidra.program.model.data.DataType: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getFixedLength(__a0: ghidra.app.plugin.core.compositeeditor.CompositeEditorModel, __a1: int, __a2: ghidra.program.model.data.DataType, __a3: bool) -> ghidra.program.model.data.DataTypeInstance: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def parseDataType(__a0: int, __a1: unicode, __a2: ghidra.app.plugin.core.compositeeditor.CompositeEditorModel, __a3: ghidra.program.model.data.DataTypeManager, __a4: ghidra.app.services.DataTypeManagerService) -> ghidra.program.model.data.DataType: ...

    @staticmethod
    def requestBytes(__a0: ghidra.app.plugin.core.compositeeditor.CompositeEditorModel, __a1: ghidra.program.model.data.DataType, __a2: int) -> ghidra.program.model.data.DataTypeInstance: ...

    @staticmethod
    def requestDtSize(__a0: ghidra.app.plugin.core.compositeeditor.CompositeEditorProvider, __a1: unicode, __a2: int, __a3: int) -> int: ...

    @staticmethod
    def resolveDataType(__a0: ghidra.program.model.data.DataType, __a1: ghidra.program.model.data.DataTypeManager, __a2: ghidra.program.model.data.DataTypeConflictHandler) -> ghidra.program.model.data.DataType: ...

    @staticmethod
    def stripWhiteSpace(__a0: unicode) -> unicode: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

