from typing import List
import ghidra.app.util.bin.format.objectiveC
import ghidra.program.model.data
import ghidra.program.model.symbol
import java.lang


class ObjectiveC1_MethodList(ghidra.app.util.bin.format.objectiveC.ObjectiveC_MethodList):
    NAME: unicode = u'objc_method_list'







    def applyTo(self, namespace: ghidra.program.model.symbol.Namespace) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getMethodCount(self) -> int: ...

    def getMethods(self) -> List[ghidra.app.util.bin.format.objectiveC.ObjectiveC_Method]: ...

    def getObsolete(self) -> ghidra.app.util.bin.format.objectiveC.ObjectiveC1_MethodList: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toDataType(self) -> ghidra.program.model.data.DataType: ...

    @staticmethod
    def toGenericDataType(state: ghidra.app.util.bin.format.objectiveC.ObjectiveC1_State) -> ghidra.program.model.data.DataType: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def methodCount(self) -> int: ...

    @property
    def obsolete(self) -> ghidra.app.util.bin.format.objectiveC.ObjectiveC1_MethodList: ...