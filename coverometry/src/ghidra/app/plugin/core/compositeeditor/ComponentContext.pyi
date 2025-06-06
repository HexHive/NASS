import ghidra.program.model.data
import java.lang


class ComponentContext(object):








    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getCompositeDataType(self) -> ghidra.program.model.data.Composite: ...

    def getDataTypeComponent(self) -> ghidra.program.model.data.DataTypeComponent: ...

    def getDataTypeManager(self) -> ghidra.program.model.data.DataTypeManager: ...

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
    def compositeDataType(self) -> ghidra.program.model.data.Composite: ...

    @property
    def dataTypeComponent(self) -> ghidra.program.model.data.DataTypeComponent: ...

    @property
    def dataTypeManager(self) -> ghidra.program.model.data.DataTypeManager: ...