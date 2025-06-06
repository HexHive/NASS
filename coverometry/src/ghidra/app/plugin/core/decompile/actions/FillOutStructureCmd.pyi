from typing import List
import ghidra.app.decompiler
import ghidra.framework.cmd
import ghidra.framework.model
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.program.model.pcode
import ghidra.util.task
import java.lang


class FillOutStructureCmd(ghidra.framework.cmd.BackgroundCommand):





    class OffsetPcodeOpPair(object):




        def __init__(self, __a0: long, __a1: ghidra.program.model.pcode.PcodeOp): ...



        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def getOffset(self) -> long: ...

        def getPcodeOp(self) -> ghidra.program.model.pcode.PcodeOp: ...

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
        def offset(self) -> long: ...

        @property
        def pcodeOp(self) -> ghidra.program.model.pcode.PcodeOp: ...

    def __init__(self, __a0: ghidra.program.model.listing.Program, __a1: ghidra.program.util.ProgramLocation, __a2: ghidra.framework.plugintool.PluginTool): ...



    @overload
    def applyTo(self, __a0: ghidra.framework.model.DomainObject) -> bool: ...

    @overload
    def applyTo(self, __a0: ghidra.framework.model.DomainObject, __a1: ghidra.util.task.TaskMonitor) -> bool: ...

    def canCancel(self) -> bool: ...

    def decompileFunction(self, __a0: ghidra.program.model.listing.Function, __a1: ghidra.app.decompiler.DecompInterface) -> ghidra.app.decompiler.DecompileResults: ...

    def dispose(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getComponentMap(self) -> ghidra.program.model.data.NoisyStructureBuilder: ...

    @staticmethod
    def getDataTypeTraceBackward(__a0: ghidra.program.model.pcode.Varnode) -> ghidra.program.model.data.DataType: ...

    @staticmethod
    def getDataTypeTraceForward(__a0: ghidra.program.model.pcode.Varnode) -> ghidra.program.model.data.DataType: ...

    def getLoadPcodeOps(self) -> List[object]: ...

    def getName(self) -> unicode: ...

    def getStatusMsg(self) -> unicode: ...

    def getStorePcodeOps(self) -> List[object]: ...

    def hasProgress(self) -> bool: ...

    def hashCode(self) -> int: ...

    def isModal(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def processStructure(self, __a0: ghidra.program.model.pcode.HighVariable, __a1: ghidra.program.model.listing.Function) -> ghidra.program.model.data.Structure: ...

    def taskCompleted(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def componentMap(self) -> ghidra.program.model.data.NoisyStructureBuilder: ...

    @property
    def loadPcodeOps(self) -> List[object]: ...

    @property
    def storePcodeOps(self) -> List[object]: ...