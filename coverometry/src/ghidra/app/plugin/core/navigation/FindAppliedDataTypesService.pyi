import ghidra.app.services
import ghidra.program.model.data
import java.lang


class FindAppliedDataTypesService(object):








    def equals(self, __a0: object) -> bool: ...

    @overload
    def findAndDisplayAppliedDataTypeAddresses(self, __a0: ghidra.program.model.data.DataType) -> None: ...

    @overload
    def findAndDisplayAppliedDataTypeAddresses(self, __a0: ghidra.program.model.data.DataType, __a1: unicode) -> None: ...

    @overload
    def findAndDisplayAppliedDataTypeAddresses(self, __a0: ghidra.program.model.data.DataType, __a1: ghidra.app.services.FieldMatcher) -> None: ...

    def getClass(self) -> java.lang.Class: ...

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

