import ghidra.program.model.address
import ghidra.program.model.pcode
import ghidra.program.model.symbol
import ghidra.trace.model
import ghidra.trace.model.thread
import java.lang


class TraceEquateReference(ghidra.program.model.symbol.EquateReference, object):








    def delete(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getAddress(self) -> ghidra.program.model.address.Address: ...

    def getClass(self) -> java.lang.Class: ...

    def getDynamicHashValue(self) -> long: ...

    def getLifespan(self) -> ghidra.trace.model.Lifespan: ...

    def getOpIndex(self) -> int: ...

    def getThread(self) -> ghidra.trace.model.thread.TraceThread: ...

    def getVarnode(self) -> ghidra.program.model.pcode.Varnode: ...

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
    def address(self) -> ghidra.program.model.address.Address: ...

    @property
    def dynamicHashValue(self) -> long: ...

    @property
    def lifespan(self) -> ghidra.trace.model.Lifespan: ...

    @property
    def opIndex(self) -> int: ...

    @property
    def thread(self) -> ghidra.trace.model.thread.TraceThread: ...

    @property
    def varnode(self) -> ghidra.program.model.pcode.Varnode: ...