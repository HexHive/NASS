import ghidra.util.task
import java.lang
import java.util


class ClosedSequenceMiner(object):




    def __init__(self, __a0: ghidra.closedpatternmining.SequenceDatabase, __a1: int): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def mineClosedSequences(self, __a0: ghidra.util.task.TaskMonitor) -> java.util.Set: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

