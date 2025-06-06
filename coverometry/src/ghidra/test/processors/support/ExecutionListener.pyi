from typing import List
import ghidra.program.model.address
import ghidra.test.processors.support
import java.lang


class ExecutionListener(ghidra.test.processors.support.TestLogger, object):








    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    @overload
    def log(self, __a0: ghidra.test.processors.support.PCodeTestGroup, __a1: unicode) -> None: ...

    @overload
    def log(self, __a0: ghidra.test.processors.support.PCodeTestGroup, __a1: unicode, __a2: java.lang.Throwable) -> None: ...

    def logRead(self, testRunner: ghidra.test.processors.support.EmulatorTestRunner, address: ghidra.program.model.address.Address, size: int, values: List[int]) -> None: ...

    @overload
    def logState(self, __a0: ghidra.test.processors.support.EmulatorTestRunner) -> None: ...

    @overload
    def logState(self, __a0: ghidra.test.processors.support.EmulatorTestRunner, __a1: ghidra.program.model.address.Address, __a2: int, __a3: int, __a4: ghidra.test.processors.support.EmulatorTestRunner.DumpFormat, __a5: unicode) -> None: ...

    def logWrite(self, testRunner: ghidra.test.processors.support.EmulatorTestRunner, address: ghidra.program.model.address.Address, size: int, values: List[int]) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def stepCompleted(self, testRunner: ghidra.test.processors.support.EmulatorTestRunner) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

