import java.lang
import java.nio


class ByteBufferUtils(object):








    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def maskedEquals(__a0: java.nio.ByteBuffer, __a1: java.nio.ByteBuffer, __a2: java.nio.ByteBuffer) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def resize(__a0: java.nio.ByteBuffer, __a1: int) -> java.nio.ByteBuffer: ...

    def toString(self) -> unicode: ...

    @staticmethod
    def upsize(__a0: java.nio.ByteBuffer) -> java.nio.ByteBuffer: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

