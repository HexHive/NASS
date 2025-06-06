from typing import List
import ghidra.program.model.address
import ghidra.test.processors.support
import ghidra.test.processors.support.PCodeTestAbstractControlBlock
import java.lang


class PCodeTestControlBlock(ghidra.test.processors.support.PCodeTestAbstractControlBlock):
    """
    PCodeTestControlBlock data is read from each binary test file and
     identified by the MAIN_CONTROL_BLOCK_MAGIC 64-bit character field value at the start of the 
     data structure.  Only one instance of this should exist within the binary.
    """

    cachedProgramPath: unicode
    testFile: ghidra.test.processors.support.PCodeTestFile







    def equals(self, __a0: object) -> bool: ...

    def getBreakOnDoneAddress(self) -> ghidra.program.model.address.Address: ...

    def getBreakOnErrorAddress(self) -> ghidra.program.model.address.Address: ...

    def getBreakOnPassAddress(self) -> ghidra.program.model.address.Address: ...

    def getClass(self) -> java.lang.Class: ...

    @overload
    def getFunctionInfo(self, functionIndex: int) -> ghidra.test.processors.support.PCodeTestAbstractControlBlock.FunctionInfo: ...

    @overload
    def getFunctionInfo(self, functionName: unicode) -> ghidra.test.processors.support.PCodeTestAbstractControlBlock.FunctionInfo: ...

    def getInfoStructureAddress(self) -> ghidra.program.model.address.Address: ...

    def getNumberFunctions(self) -> int: ...

    def getPrintfBufferAddress(self) -> ghidra.program.model.address.Address: ...

    def getSprintf5Address(self) -> ghidra.program.model.address.Address: ...

    def getTestGroups(self) -> List[ghidra.test.processors.support.PCodeTestGroup]: ...

    def getTestResults(self) -> ghidra.test.processors.support.PCodeTestResults: ...

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
    def breakOnDoneAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def breakOnErrorAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def breakOnPassAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def printfBufferAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def sprintf5Address(self) -> ghidra.program.model.address.Address: ...

    @property
    def testGroups(self) -> List[object]: ...

    @property
    def testResults(self) -> ghidra.test.processors.support.PCodeTestResults: ...