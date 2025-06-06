import java.lang
import java.net
import java.nio.channels
import java.util


class GhidraSSLServerSocket(java.net.ServerSocket):








    def accept(self) -> java.net.Socket: ...

    @overload
    def bind(self, __a0: java.net.SocketAddress) -> None: ...

    @overload
    def bind(self, __a0: java.net.SocketAddress, __a1: int) -> None: ...

    def close(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getChannel(self) -> java.nio.channels.ServerSocketChannel: ...

    def getClass(self) -> java.lang.Class: ...

    def getInetAddress(self) -> java.net.InetAddress: ...

    def getLocalPort(self) -> int: ...

    def getLocalSocketAddress(self) -> java.net.SocketAddress: ...

    def getOption(self, __a0: java.net.SocketOption) -> object: ...

    def getReceiveBufferSize(self) -> int: ...

    def getReuseAddress(self) -> bool: ...

    def getSoTimeout(self) -> int: ...

    def hashCode(self) -> int: ...

    def isBound(self) -> bool: ...

    def isClosed(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setOption(self, __a0: java.net.SocketOption, __a1: object) -> java.net.ServerSocket: ...

    def setPerformancePreferences(self, __a0: int, __a1: int, __a2: int) -> None: ...

    def setReceiveBufferSize(self, __a0: int) -> None: ...

    def setReuseAddress(self, __a0: bool) -> None: ...

    def setSoTimeout(self, __a0: int) -> None: ...

    @staticmethod
    def setSocketFactory(__a0: java.net.SocketImplFactory) -> None: ...

    def supportedOptions(self) -> java.util.Set: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

