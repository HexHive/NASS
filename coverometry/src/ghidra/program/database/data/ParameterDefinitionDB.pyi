import ghidra.program.model.data
import ghidra.program.model.listing
import java.lang


class ParameterDefinitionDB(object, ghidra.program.model.data.ParameterDefinition):
    """
    Database implementation for a Parameter.
    """









    def compareTo(self, __a0: object) -> int: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getComment(self) -> unicode: ...

    def getDataType(self) -> ghidra.program.model.data.DataType: ...

    def getLength(self) -> int: ...

    def getName(self) -> unicode: ...

    def getOrdinal(self) -> int: ...

    def hashCode(self) -> int: ...

    @overload
    def isEquivalent(self, parm: ghidra.program.model.data.ParameterDefinition) -> bool: ...

    @overload
    def isEquivalent(self, otherVar: ghidra.program.model.listing.Variable) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setComment(self, comment: unicode) -> None: ...

    def setDataType(self, type: ghidra.program.model.data.DataType) -> None: ...

    def setName(self, name: unicode) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

