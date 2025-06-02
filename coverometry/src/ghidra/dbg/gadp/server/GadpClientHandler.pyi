import ghidra.comm.service
import java.lang


class GadpClientHandler(ghidra.comm.service.AbstractAsyncClientHandler):




    def __init__(self, __a0: ghidra.dbg.gadp.server.AbstractGadpServer, __a1: java.nio.channels.AsynchronousSocketChannel): ...



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

