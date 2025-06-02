from typing import List
import com.google.protobuf
import ghidra.dbg.gadp
import ghidra.dbg.target
import java.lang
import java.util
import java.util.concurrent


class GadpRegistry(java.lang.Enum):
    MIXIN_REGISTRY: java.util.Map = {<type 'ghidra.dbg.target.TargetBreakpointSpecContainer'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetBreakpointSpecContainer'>, <type 'ghidra.dbg.target.TargetConfigurable'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetConfigurable'>, <type 'ghidra.dbg.target.TargetMemoryRegion'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetMemoryRegion'>, <type 'ghidra.dbg.target.TargetBreakpointLocation'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetBreakpointLocation'>, <type 'ghidra.dbg.target.TargetTogglable'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetTogglable'>, <type 'ghidra.dbg.target.TargetModuleContainer'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetModuleContainer'>, <type 'ghidra.dbg.target.TargetBreakpointLocationContainer'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetBreakpointLocationContainer'>, <type 'ghidra.dbg.target.TargetSymbol'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetSymbol'>, <type 'ghidra.dbg.target.TargetDetachable'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetDetachable'>, <type 'ghidra.dbg.target.TargetEventScope'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetEventScope'>, <type 'ghidra.dbg.target.TargetSteppable'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetSteppable'>, <type 'ghidra.dbg.target.TargetFocusScope'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetFocusScope'>, <type 'ghidra.dbg.target.TargetRegisterContainer'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetRegisterContainer'>, <type 'ghidra.dbg.target.TargetResumable'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetResumable'>, <type 'ghidra.dbg.target.TargetInterpreter'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetInterpreter'>, <type 'ghidra.dbg.target.TargetAccessConditioned'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetAccessConditioned'>, <type 'ghidra.dbg.target.TargetDeletable'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetDeletable'>, <type 'ghidra.dbg.target.TargetMemory'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetMemory'>, <type 'ghidra.dbg.target.TargetInterruptible'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetInterruptible'>, <type 'ghidra.dbg.target.TargetRegisterBank'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetRegisterBank'>, <type 'ghidra.dbg.target.TargetConsole'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetConsole'>, <type 'ghidra.dbg.target.TargetStackFrame'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetStackFrame'>, <type 'ghidra.dbg.target.TargetAttacher'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetAttacher'>, <type 'ghidra.dbg.target.TargetLauncher'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetLauncher'>, <type 'ghidra.dbg.target.TargetStack'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetStack'>, <type 'ghidra.dbg.target.TargetRegister'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetRegister'>, <type 'ghidra.dbg.target.TargetAggregate'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetAggregate'>, <type 'ghidra.dbg.target.TargetEnvironment'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetEnvironment'>, <type 'ghidra.dbg.target.TargetModule'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetModule'>, <type 'ghidra.dbg.target.TargetActiveScope'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetActiveScope'>, <type 'ghidra.dbg.target.TargetAttachable'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetAttachable'>, <type 'ghidra.dbg.target.TargetThread'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetThread'>, <type 'ghidra.dbg.target.TargetDataTypeNamespace'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetDataTypeNamespace'>, <type 'ghidra.dbg.target.TargetProcess'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetProcess'>, <type 'ghidra.dbg.target.TargetBreakpointSpec'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetBreakpointSpec'>, <type 'ghidra.dbg.target.TargetKillable'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetKillable'>, <type 'ghidra.dbg.target.TargetExecutionStateful'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetExecutionStateful'>, <type 'ghidra.dbg.target.TargetNamedDataType'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetNamedDataType'>, <type 'ghidra.dbg.target.TargetSectionContainer'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetSectionContainer'>, <type 'ghidra.dbg.target.TargetMethod'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetMethod'>, <type 'ghidra.dbg.target.TargetSection'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetSection'>, <type 'ghidra.dbg.target.TargetDataTypeMember'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetDataTypeMember'>, <type 'ghidra.dbg.target.TargetSymbolNamespace'>: <type 'ghidra.dbg.gadp.client.GadpClientTargetSymbolNamespace'>}




    class ServerInvoker(object):








        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def hashCode(self) -> int: ...

        def invoke(self, __a0: ghidra.dbg.target.TargetObject, __a1: object) -> java.util.concurrent.CompletableFuture: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...






    class InvocationBuilder(object):








        def buildMessage(self, __a0: unicode, __a1: List[object]) -> com.google.protobuf.Message.Builder: ...

        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

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







    @overload
    def compareTo(self, __a0: java.lang.Enum) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def describeConstable(self) -> java.util.Optional: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDeclaringClass(self) -> java.lang.Class: ...

    @staticmethod
    def getInterfaceNames(__a0: ghidra.dbg.target.TargetObject) -> List[object]: ...

    @staticmethod
    def getMixins(__a0: List[object]) -> List[object]: ...

    def hashCode(self) -> int: ...

    def name(self) -> unicode: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def ordinal(self) -> int: ...

    @staticmethod
    def registerInterface(__a0: java.lang.Class, __a1: java.lang.Class) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    @staticmethod
    def valueOf(__a0: unicode) -> ghidra.dbg.gadp.GadpRegistry: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.dbg.gadp.GadpRegistry]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

