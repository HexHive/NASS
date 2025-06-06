from typing import List
import ghidra.bitpatterns.info
import java.lang


class FileBitPatternInfoReader(object):




    @overload
    def __init__(self, __a0: java.io.File, __a1: java.awt.Component): ...

    @overload
    def __init__(self, __a0: ghidra.program.model.listing.Program, __a1: ghidra.bitpatterns.info.DataGatheringParams, __a2: java.awt.Component): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getContextRegisterExtent(self) -> ghidra.bitpatterns.info.ContextRegisterExtent: ...

    def getDataGatheringParams(self) -> ghidra.bitpatterns.info.DataGatheringParams: ...

    def getFInfoList(self) -> List[object]: ...

    def getFilteredAddresses(self, __a0: ghidra.bitpatterns.info.ContextRegisterFilter) -> List[object]: ...

    def getNumFiles(self) -> int: ...

    def getNumFuncs(self) -> int: ...

    def getStartingAddresses(self) -> List[object]: ...

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
    def FInfoList(self) -> List[object]: ...

    @property
    def contextRegisterExtent(self) -> ghidra.bitpatterns.info.ContextRegisterExtent: ...

    @property
    def dataGatheringParams(self) -> ghidra.bitpatterns.info.DataGatheringParams: ...

    @property
    def numFiles(self) -> int: ...

    @property
    def numFuncs(self) -> int: ...

    @property
    def startingAddresses(self) -> List[object]: ...