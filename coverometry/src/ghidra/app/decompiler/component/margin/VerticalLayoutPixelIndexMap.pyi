from typing import List
import ghidra.app.decompiler.component.margin
import java.lang


class VerticalLayoutPixelIndexMap(object, ghidra.app.decompiler.component.margin.LayoutPixelIndexMap):
    """
    An implementation of LayoutPixelIndexMap for vertical coordinates
 
 
     This class implements #getIndex(int) in log time and #getPixel(BigInteger) in
     constant time.
    """





    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getIndex(self, pixel: int) -> long: ...

    def getPixel(self, index: long) -> int: ...

    def hashCode(self) -> int: ...

    def layoutsChanged(self, __a0: List[object]) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

