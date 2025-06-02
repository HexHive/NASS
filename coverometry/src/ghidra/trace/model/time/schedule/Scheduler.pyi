import ghidra.pcode.emu
import ghidra.trace.model
import ghidra.trace.model.thread
import ghidra.trace.model.time.schedule
import ghidra.util.task
import java.lang


class Scheduler(object):





    class RunResult(object):








        def equals(self, __a0: object) -> bool: ...

        def error(self) -> java.lang.Throwable: ...

        def getClass(self) -> java.lang.Class: ...

        def hashCode(self) -> int: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def schedule(self) -> ghidra.trace.model.time.schedule.TraceSchedule: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...






    class RecordRunResult(java.lang.Record, ghidra.trace.model.time.schedule.Scheduler.RunResult):




        def __init__(self, __a0: ghidra.trace.model.time.schedule.TraceSchedule, __a1: java.lang.Throwable): ...



        def equals(self, __a0: object) -> bool: ...

        def error(self) -> java.lang.Throwable: ...

        def getClass(self) -> java.lang.Class: ...

        def hashCode(self) -> int: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def schedule(self) -> ghidra.trace.model.time.schedule.TraceSchedule: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...







    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def nextSlice(self, __a0: ghidra.trace.model.Trace) -> ghidra.trace.model.time.schedule.TickStep: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def oneThread(__a0: ghidra.trace.model.thread.TraceThread) -> ghidra.trace.model.time.schedule.Scheduler: ...

    def run(self, __a0: ghidra.trace.model.Trace, __a1: ghidra.trace.model.thread.TraceThread, __a2: ghidra.pcode.emu.PcodeMachine, __a3: ghidra.util.task.TaskMonitor) -> ghidra.trace.model.time.schedule.Scheduler.RunResult: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

