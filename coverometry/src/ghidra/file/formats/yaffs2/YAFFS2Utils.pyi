from typing import List
import ghidra.program.model.listing
import java.lang


class YAFFS2Utils(object):




    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def isYAFFS2Image(__a0: ghidra.program.model.listing.Program) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def parseDateTime(__a0: List[int], __a1: int, __a2: int) -> unicode: ...

    @staticmethod
    def parseFileSize(__a0: List[int], __a1: int, __a2: int) -> long: ...

    @staticmethod
    def parseInteger(__a0: List[int], __a1: int, __a2: int) -> long: ...

    @staticmethod
    def parseName(__a0: List[int], __a1: int, __a2: int) -> unicode: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

