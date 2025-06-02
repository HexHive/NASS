from typing import List
import ghidra.app.plugin.core.debug.stack
import ghidra.app.services
import ghidra.pcode.exec
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.pcode
import java.lang
import java.util.concurrent


class SavedRegisterMap(object):




    @overload
    def __init__(self): ...

    @overload
    def __init__(self, __a0: java.util.TreeMap): ...



    def equals(self, __a0: object) -> bool: ...

    def fork(self) -> ghidra.app.plugin.core.debug.stack.SavedRegisterMap: ...

    def getClass(self) -> java.lang.Class: ...

    def getVar(self, __a0: ghidra.pcode.exec.PcodeExecutorState, __a1: ghidra.program.model.address.Address, __a2: int, __a3: ghidra.pcode.exec.PcodeExecutorStatePiece.Reason) -> object: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @overload
    def put(self, __a0: ghidra.program.model.address.AddressRange, __a1: ghidra.program.model.address.Address) -> None: ...

    @overload
    def put(self, __a0: ghidra.program.model.address.AddressRange, __a1: ghidra.program.model.address.AddressRange) -> None: ...

    @overload
    def put(self, __a0: ghidra.program.model.lang.Register, __a1: ghidra.program.model.pcode.Varnode) -> None: ...

    def setVar(self, __a0: ghidra.app.services.DebuggerControlService.StateEditor, __a1: ghidra.program.model.address.Address, __a2: List[int]) -> java.util.concurrent.CompletableFuture: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

