from typing import List
import java.lang


class DataGatheringParams(object):




    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getContextRegisterList(__a0: unicode) -> List[object]: ...

    def getContextRegisters(self) -> List[object]: ...

    def getNumFirstBytes(self) -> int: ...

    def getNumFirstInstructions(self) -> int: ...

    def getNumPreBytes(self) -> int: ...

    def getNumPreInstructions(self) -> int: ...

    def getNumReturnBytes(self) -> int: ...

    def getNumReturnInstructions(self) -> int: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setContextRegisters(self, __a0: List[object]) -> None: ...

    def setNumFirstBytes(self, __a0: int) -> None: ...

    def setNumFirstInstructions(self, __a0: int) -> None: ...

    def setNumPreBytes(self, __a0: int) -> None: ...

    def setNumPreInstructions(self, __a0: int) -> None: ...

    def setNumReturnBytes(self, __a0: int) -> None: ...

    def setNumReturnInstructions(self, __a0: int) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def contextRegisters(self) -> List[object]: ...

    @contextRegisters.setter
    def contextRegisters(self, value: List[object]) -> None: ...

    @property
    def numFirstBytes(self) -> int: ...

    @numFirstBytes.setter
    def numFirstBytes(self, value: int) -> None: ...

    @property
    def numFirstInstructions(self) -> int: ...

    @numFirstInstructions.setter
    def numFirstInstructions(self, value: int) -> None: ...

    @property
    def numPreBytes(self) -> int: ...

    @numPreBytes.setter
    def numPreBytes(self, value: int) -> None: ...

    @property
    def numPreInstructions(self) -> int: ...

    @numPreInstructions.setter
    def numPreInstructions(self, value: int) -> None: ...

    @property
    def numReturnBytes(self) -> int: ...

    @numReturnBytes.setter
    def numReturnBytes(self, value: int) -> None: ...

    @property
    def numReturnInstructions(self) -> int: ...

    @numReturnInstructions.setter
    def numReturnInstructions(self, value: int) -> None: ...