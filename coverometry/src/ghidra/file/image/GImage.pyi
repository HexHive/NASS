import java.lang
import javax.swing


class GImage(object):




    def __init__(self, __a0: int, __a1: int, __a2: ghidra.file.image.GImageFormat, __a3: java.io.InputStream, __a4: long): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toGIF(self) -> javax.swing.Icon: ...

    def toJPEG(self) -> javax.swing.Icon: ...

    def toPNG(self) -> javax.swing.Icon: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

