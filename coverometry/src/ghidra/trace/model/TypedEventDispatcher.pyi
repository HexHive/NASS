import ghidra.framework.model
import ghidra.trace.model
import ghidra.trace.util
import java.lang


class TypedEventDispatcher(object):





    class AffectedAndValuesOnlyHandler(ghidra.trace.model.TypedEventDispatcher.EventRecordHandler, object):








        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        @overload
        def handle(self, __a0: ghidra.trace.util.TraceChangeRecord) -> None: ...

        @overload
        def handle(self, __a0: object, __a1: object, __a2: object) -> None: ...

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






    class SpaceValuesHandler(ghidra.trace.model.TypedEventDispatcher.EventRecordHandler, object):








        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        @overload
        def handle(self, __a0: ghidra.trace.util.TraceChangeRecord) -> None: ...

        @overload
        def handle(self, __a0: ghidra.trace.util.TraceAddressSpace, __a1: object, __a2: object) -> None: ...

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






    class AffectedObjectHandler(ghidra.trace.model.TypedEventDispatcher.EventRecordHandler, object):








        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        @overload
        def handle(self, __a0: ghidra.trace.util.TraceChangeRecord) -> None: ...

        @overload
        def handle(self, __a0: ghidra.trace.util.TraceAddressSpace, __a1: object) -> None: ...

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






    class FullEventRecordHandler(ghidra.trace.model.TypedEventDispatcher.EventRecordHandler, object):








        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        @overload
        def handle(self, __a0: ghidra.trace.util.TraceChangeRecord) -> None: ...

        @overload
        def handle(self, __a0: ghidra.trace.util.TraceAddressSpace, __a1: object, __a2: object, __a3: object) -> None: ...

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






    class AffectedObjectOnlyHandler(ghidra.trace.model.TypedEventDispatcher.EventRecordHandler, object):








        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        @overload
        def handle(self, __a0: ghidra.trace.util.TraceChangeRecord) -> None: ...

        @overload
        def handle(self, __a0: object) -> None: ...

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






    class IgnoreAllHandler(ghidra.trace.model.TypedEventDispatcher.EventRecordHandler, object):








        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        @overload
        def handle(self) -> None: ...

        @overload
        def handle(self, __a0: ghidra.trace.util.TraceChangeRecord) -> None: ...

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






    class EventRecordHandler(object):








        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def handle(self, __a0: ghidra.trace.util.TraceChangeRecord) -> None: ...

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






    class ValuesOnlyHandler(ghidra.trace.model.TypedEventDispatcher.EventRecordHandler, object):








        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        @overload
        def handle(self, __a0: ghidra.trace.util.TraceChangeRecord) -> None: ...

        @overload
        def handle(self, __a0: object, __a1: object) -> None: ...

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






    class IgnoreValuesHandler(ghidra.trace.model.TypedEventDispatcher.EventRecordHandler, object):








        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        @overload
        def handle(self, __a0: ghidra.trace.util.TraceAddressSpace) -> None: ...

        @overload
        def handle(self, __a0: ghidra.trace.util.TraceChangeRecord) -> None: ...

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



    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def handleChangeRecord(self, __a0: ghidra.framework.model.DomainObjectChangeRecord) -> None: ...

    def handleTraceChangeRecord(self, __a0: ghidra.trace.util.TraceChangeRecord) -> None: ...

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

