import ghidra.feature.fid.db
import ghidra.feature.fid.debug
import ghidra.feature.fid.service
import java.lang


class FidDebugUtils(object):




    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def openFunctionWindow(__a0: ghidra.feature.fid.db.FunctionRecord, __a1: ghidra.feature.fid.service.FidService, __a2: ghidra.feature.fid.db.FidQueryService) -> None: ...

    @staticmethod
    def searchByDomainPath(__a0: unicode, __a1: ghidra.feature.fid.service.FidService, __a2: ghidra.feature.fid.db.FidQueryService) -> ghidra.feature.fid.debug.FidSearchResultFrame: ...

    @staticmethod
    def searchByFullHash(__a0: long, __a1: ghidra.feature.fid.service.FidService, __a2: ghidra.feature.fid.db.FidQueryService) -> ghidra.feature.fid.debug.FidSearchResultFrame: ...

    @staticmethod
    def searchByFunctionID(__a0: long, __a1: ghidra.feature.fid.service.FidService, __a2: ghidra.feature.fid.db.FidQueryService) -> ghidra.feature.fid.debug.FidSearchResultFrame: ...

    @staticmethod
    def searchByName(__a0: unicode, __a1: ghidra.feature.fid.service.FidService, __a2: ghidra.feature.fid.db.FidQueryService) -> ghidra.feature.fid.debug.FidSearchResultFrame: ...

    @staticmethod
    def searchBySpecificHash(__a0: long, __a1: ghidra.feature.fid.service.FidService, __a2: ghidra.feature.fid.db.FidQueryService) -> ghidra.feature.fid.debug.FidSearchResultFrame: ...

    def toString(self) -> unicode: ...

    @staticmethod
    def validateHashText(__a0: unicode, __a1: unicode) -> long: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

