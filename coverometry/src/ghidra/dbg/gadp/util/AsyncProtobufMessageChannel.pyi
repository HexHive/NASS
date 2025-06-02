import com.google.protobuf
import ghidra.dbg.gadp.util
import java.lang
import java.nio
import java.util.concurrent


class AsyncProtobufMessageChannel(object):
    DEFAULT_BUFFER_SIZE: int = 4096
    LOG_READ: bool = False
    LOG_WRITE: bool = False




    class IOFunction(object):








        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def hashCode(self) -> int: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def read(self, __a0: com.google.protobuf.CodedInputStream) -> com.google.protobuf.Message: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...



    @overload
    def __init__(self, __a0: java.nio.channels.AsynchronousByteChannel): ...

    @overload
    def __init__(self, __a0: java.nio.channels.AsynchronousByteChannel, __a1: int): ...



    def close(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def marshall(__a0: com.google.protobuf.Message, __a1: java.nio.ByteBuffer) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def read(self, __a0: ghidra.dbg.gadp.util.AsyncProtobufMessageChannel.IOFunction) -> java.util.concurrent.CompletableFuture: ...

    def toString(self) -> unicode: ...

    @staticmethod
    def unmarshall(__a0: ghidra.dbg.gadp.util.AsyncProtobufMessageChannel.IOFunction, __a1: java.nio.ByteBuffer) -> com.google.protobuf.Message: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    def write(self, __a0: com.google.protobuf.GeneratedMessageV3) -> java.util.concurrent.CompletableFuture: ...

