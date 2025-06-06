import ghidra.trace.model
import ghidra.trace.model.thread
import ghidra.trace.model.time.schedule
import java.lang


class TraceSnapshot(object):








    def delete(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDescription(self) -> unicode: ...

    def getEventThread(self) -> ghidra.trace.model.thread.TraceThread: ...

    def getKey(self) -> long: ...

    def getRealTime(self) -> long: ...

    def getSchedule(self) -> ghidra.trace.model.time.schedule.TraceSchedule: ...

    def getScheduleString(self) -> unicode: ...

    def getTrace(self) -> ghidra.trace.model.Trace: ...

    def getVersion(self) -> long: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setDescription(self, __a0: unicode) -> None: ...

    def setEventThread(self, __a0: ghidra.trace.model.thread.TraceThread) -> None: ...

    def setRealTime(self, __a0: long) -> None: ...

    def setSchedule(self, __a0: ghidra.trace.model.time.schedule.TraceSchedule) -> None: ...

    def setVersion(self, __a0: long) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def description(self) -> unicode: ...

    @description.setter
    def description(self, value: unicode) -> None: ...

    @property
    def eventThread(self) -> ghidra.trace.model.thread.TraceThread: ...

    @eventThread.setter
    def eventThread(self, value: ghidra.trace.model.thread.TraceThread) -> None: ...

    @property
    def key(self) -> long: ...

    @property
    def realTime(self) -> long: ...

    @realTime.setter
    def realTime(self, value: long) -> None: ...

    @property
    def schedule(self) -> ghidra.trace.model.time.schedule.TraceSchedule: ...

    @schedule.setter
    def schedule(self, value: ghidra.trace.model.time.schedule.TraceSchedule) -> None: ...

    @property
    def scheduleString(self) -> unicode: ...

    @property
    def trace(self) -> ghidra.trace.model.Trace: ...

    @property
    def version(self) -> long: ...

    @version.setter
    def version(self, value: long) -> None: ...