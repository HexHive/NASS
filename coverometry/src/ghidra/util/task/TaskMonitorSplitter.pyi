from typing import List
import ghidra.util.task
import java.lang


class TaskMonitorSplitter(object):
    MONITOR_SIZE: int



    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def splitTaskMonitor(monitor: ghidra.util.task.TaskMonitor, n: int) -> List[ghidra.util.task.TaskMonitor]: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

