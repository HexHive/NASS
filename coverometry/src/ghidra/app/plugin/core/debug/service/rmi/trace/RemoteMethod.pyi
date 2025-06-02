import ghidra.app.plugin.core.debug.service.rmi.trace
import ghidra.dbg.target.schema
import ghidra.trace.model
import java.lang
import java.util


class RemoteMethod(object):





    class RecordRemoteMethod(java.lang.Record, ghidra.app.plugin.core.debug.service.rmi.trace.RemoteMethod):




        def __init__(self, __a0: ghidra.app.plugin.core.debug.service.rmi.trace.TraceRmiHandler, __a1: unicode, __a2: ghidra.app.plugin.core.debug.service.rmi.trace.RemoteMethod.Action, __a3: unicode, __a4: java.util.Map, __a5: ghidra.dbg.target.schema.TargetObjectSchema.SchemaName): ...



        def action(self) -> ghidra.app.plugin.core.debug.service.rmi.trace.RemoteMethod.Action: ...

        @staticmethod
        def checkType(__a0: unicode, __a1: ghidra.dbg.target.schema.TargetObjectSchema, __a2: object) -> None: ...

        def description(self) -> unicode: ...

        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def handler(self) -> ghidra.app.plugin.core.debug.service.rmi.trace.TraceRmiHandler: ...

        def hashCode(self) -> int: ...

        def invoke(self, __a0: java.util.Map) -> object: ...

        def invokeAsync(self, __a0: java.util.Map) -> ghidra.app.plugin.core.debug.service.rmi.trace.RemoteAsyncResult: ...

        def name(self) -> unicode: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def parameters(self) -> java.util.Map: ...

        def retType(self) -> ghidra.dbg.target.schema.TargetObjectSchema.SchemaName: ...

        def toString(self) -> unicode: ...

        def validate(self, __a0: java.util.Map) -> ghidra.trace.model.Trace: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...






    class Action(java.lang.Record):
        ACTIVATE: ghidra.app.plugin.core.debug.service.rmi.trace.RemoteMethod.Action = Action[name=activate]
        ATTACH: ghidra.app.plugin.core.debug.service.rmi.trace.RemoteMethod.Action = Action[name=attach]
        BREAK_ACCESS: ghidra.app.plugin.core.debug.service.rmi.trace.RemoteMethod.Action = Action[name=break_access]
        BREAK_EXT: ghidra.app.plugin.core.debug.service.rmi.trace.RemoteMethod.Action = Action[name=break_ext]
        BREAK_HW_EXECUTE: ghidra.app.plugin.core.debug.service.rmi.trace.RemoteMethod.Action = Action[name=break_hw_execute]
        BREAK_READ: ghidra.app.plugin.core.debug.service.rmi.trace.RemoteMethod.Action = Action[name=break_read]
        BREAK_SW_EXECUTE: ghidra.app.plugin.core.debug.service.rmi.trace.RemoteMethod.Action = Action[name=break_sw_execute]
        BREAK_WRITE: ghidra.app.plugin.core.debug.service.rmi.trace.RemoteMethod.Action = Action[name=break_write]
        CONNECT: ghidra.app.plugin.core.debug.service.rmi.trace.RemoteMethod.Action = Action[name=connect]
        DELETE: ghidra.app.plugin.core.debug.service.rmi.trace.RemoteMethod.Action = Action[name=delete]
        DETACH: ghidra.app.plugin.core.debug.service.rmi.trace.RemoteMethod.Action = Action[name=detach]
        EXECUTE: ghidra.app.plugin.core.debug.service.rmi.trace.RemoteMethod.Action = Action[name=execute]
        FOCUS: ghidra.app.plugin.core.debug.service.rmi.trace.RemoteMethod.Action = Action[name=focus]
        INTERRUPT: ghidra.app.plugin.core.debug.service.rmi.trace.RemoteMethod.Action = Action[name=interrupt]
        KILL: ghidra.app.plugin.core.debug.service.rmi.trace.RemoteMethod.Action = Action[name=kill]
        LAUNCH: ghidra.app.plugin.core.debug.service.rmi.trace.RemoteMethod.Action = Action[name=launch]
        READ_MEM: ghidra.app.plugin.core.debug.service.rmi.trace.RemoteMethod.Action = Action[name=read_mem]
        REFRESH: ghidra.app.plugin.core.debug.service.rmi.trace.RemoteMethod.Action = Action[name=refresh]
        RESUME: ghidra.app.plugin.core.debug.service.rmi.trace.RemoteMethod.Action = Action[name=resume]
        STEP_BACK: ghidra.app.plugin.core.debug.service.rmi.trace.RemoteMethod.Action = Action[name=step_back]
        STEP_EXT: ghidra.app.plugin.core.debug.service.rmi.trace.RemoteMethod.Action = Action[name=step_ext]
        STEP_INTO: ghidra.app.plugin.core.debug.service.rmi.trace.RemoteMethod.Action = Action[name=step_into]
        STEP_OUT: ghidra.app.plugin.core.debug.service.rmi.trace.RemoteMethod.Action = Action[name=step_out]
        STEP_OVER: ghidra.app.plugin.core.debug.service.rmi.trace.RemoteMethod.Action = Action[name=step_over]
        STEP_SKIP: ghidra.app.plugin.core.debug.service.rmi.trace.RemoteMethod.Action = Action[name=step_skip]
        TOGGLE: ghidra.app.plugin.core.debug.service.rmi.trace.RemoteMethod.Action = Action[name=toggle]
        WRITE_MEM: ghidra.app.plugin.core.debug.service.rmi.trace.RemoteMethod.Action = Action[name=write_mem]
        WRITE_REG: ghidra.app.plugin.core.debug.service.rmi.trace.RemoteMethod.Action = Action[name=write_reg]



        def __init__(self, __a0: unicode): ...



        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def hashCode(self) -> int: ...

        def name(self) -> unicode: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...







    def action(self) -> ghidra.app.plugin.core.debug.service.rmi.trace.RemoteMethod.Action: ...

    @staticmethod
    def checkType(__a0: unicode, __a1: ghidra.dbg.target.schema.TargetObjectSchema, __a2: object) -> None: ...

    def description(self) -> unicode: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def invoke(self, __a0: java.util.Map) -> object: ...

    def invokeAsync(self, __a0: java.util.Map) -> ghidra.app.plugin.core.debug.service.rmi.trace.RemoteAsyncResult: ...

    def name(self) -> unicode: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def parameters(self) -> java.util.Map: ...

    def retType(self) -> ghidra.dbg.target.schema.TargetObjectSchema.SchemaName: ...

    def toString(self) -> unicode: ...

    def validate(self, __a0: java.util.Map) -> ghidra.trace.model.Trace: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

