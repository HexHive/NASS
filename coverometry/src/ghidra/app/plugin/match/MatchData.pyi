from typing import List
import ghidra.app.plugin.match
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.util.task
import java.lang


class MatchData(object):








    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def matchData(aProgram: ghidra.program.model.listing.Program, setA: ghidra.program.model.address.AddressSetView, bProgram: ghidra.program.model.listing.Program, setB: ghidra.program.model.address.AddressSetView, minimumDataSize: int, maximumDataSize: int, alignment: int, skipHomogenousData: bool, includeOneToOne: bool, includeNonOneToOne: bool, monitor: ghidra.util.task.TaskMonitor) -> List[ghidra.app.plugin.match.MatchedData]: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

