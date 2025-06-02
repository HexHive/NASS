import ghidra.framework.data
import ghidra.framework.model
import ghidra.util.task
import java.lang


class OpenedDomainFile(object, java.lang.AutoCloseable):
    content: ghidra.framework.model.DomainObject



    def __init__(self, __a0: java.lang.Class, __a1: ghidra.framework.model.DomainFile, __a2: bool, __a3: bool, __a4: ghidra.util.task.TaskMonitor): ...



    def close(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @overload
    @staticmethod
    def open(__a0: java.lang.Class, __a1: ghidra.framework.model.DomainFile, __a2: ghidra.util.task.TaskMonitor) -> ghidra.framework.data.OpenedDomainFile: ...

    @overload
    @staticmethod
    def open(__a0: java.lang.Class, __a1: ghidra.framework.model.DomainFile, __a2: bool, __a3: bool, __a4: ghidra.util.task.TaskMonitor) -> ghidra.framework.data.OpenedDomainFile: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

