from typing import List
import ghidra.app.decompiler
import ghidra.app.extension.datatype.finder
import ghidra.app.services
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import java.lang


class AnonymousVariableAccessDR(ghidra.app.extension.datatype.finder.VariableAccessDR):








    def accumulateMatches(self, __a0: ghidra.program.model.data.DataType, __a1: ghidra.app.services.FieldMatcher, __a2: List[object]) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    @overload
    def getAddress(self) -> ghidra.program.model.address.Address: ...

    @overload
    def getAddress(self, __a0: ghidra.app.extension.datatype.finder.DecompilerVariable) -> ghidra.program.model.address.Address: ...

    @staticmethod
    def getBaseType(__a0: ghidra.program.model.data.DataType) -> ghidra.program.model.data.DataType: ...

    def getClass(self) -> java.lang.Class: ...

    def getDataType(self) -> ghidra.program.model.data.DataType: ...

    @staticmethod
    def getFieldDataType(__a0: ghidra.app.decompiler.ClangFieldToken) -> ghidra.program.model.data.DataType: ...

    def getFunction(self) -> ghidra.program.model.listing.Function: ...

    def getLine(self) -> ghidra.app.decompiler.ClangLine: ...

    def getVariable(self) -> ghidra.app.extension.datatype.finder.DecompilerVariable: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def isEqual(__a0: ghidra.program.model.data.DataType, __a1: ghidra.program.model.data.DataType) -> bool: ...

    @staticmethod
    def isEquivalent(__a0: ghidra.program.model.data.DataType, __a1: ghidra.program.model.data.DataType) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

