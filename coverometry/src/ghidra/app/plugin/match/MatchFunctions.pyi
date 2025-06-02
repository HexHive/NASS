from typing import List
import ghidra.app.plugin.match
import ghidra.app.plugin.match.MatchFunctions
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.util.task
import java.lang


class MatchFunctions(object):
    """
    This class does the work of matching subroutines. Every subroutine
     in the current program is hashed and the start address is put into a 
     table. There are often identical subroutines which may have the same hash
     value. Then the subroutines in the other program are hashed as well. All unique
     match pairs are returned as matches. The next step would be to use call graph
     information or address order to get additional matches.
    """






    class MatchedFunctions(object):








        def equals(self, __a0: object) -> bool: ...

        def getAFunctionAddress(self) -> ghidra.program.model.address.Address: ...

        def getAMatchNum(self) -> int: ...

        def getAProgram(self) -> ghidra.program.model.listing.Program: ...

        def getBFunctionAddress(self) -> ghidra.program.model.address.Address: ...

        def getBMatchNum(self) -> int: ...

        def getBProgram(self) -> ghidra.program.model.listing.Program: ...

        def getClass(self) -> java.lang.Class: ...

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
        def AFunctionAddress(self) -> ghidra.program.model.address.Address: ...

        @property
        def AMatchNum(self) -> int: ...

        @property
        def AProgram(self) -> ghidra.program.model.listing.Program: ...

        @property
        def BFunctionAddress(self) -> ghidra.program.model.address.Address: ...

        @property
        def BMatchNum(self) -> int: ...

        @property
        def BProgram(self) -> ghidra.program.model.listing.Program: ...





    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def matchFunctions(aProgram: ghidra.program.model.listing.Program, setA: ghidra.program.model.address.AddressSetView, bProgram: ghidra.program.model.listing.Program, setB: ghidra.program.model.address.AddressSetView, minimumFunctionSize: int, includeOneToOne: bool, includeNonOneToOne: bool, hasher: ghidra.app.plugin.match.FunctionHasher, monitor: ghidra.util.task.TaskMonitor) -> List[ghidra.app.plugin.match.MatchFunctions.MatchedFunctions]: ...

    @overload
    @staticmethod
    def matchOneFunction(aProgram: ghidra.program.model.listing.Program, aEntryPoint: ghidra.program.model.address.Address, bProgram: ghidra.program.model.listing.Program, hasher: ghidra.app.plugin.match.FunctionHasher, monitor: ghidra.util.task.TaskMonitor) -> List[ghidra.app.plugin.match.MatchFunctions.MatchedFunctions]: ...

    @overload
    @staticmethod
    def matchOneFunction(aProgram: ghidra.program.model.listing.Program, aEntryPoint: ghidra.program.model.address.Address, bProgram: ghidra.program.model.listing.Program, bAddressSet: ghidra.program.model.address.AddressSetView, hasher: ghidra.app.plugin.match.FunctionHasher, monitor: ghidra.util.task.TaskMonitor) -> List[ghidra.app.plugin.match.MatchFunctions.MatchedFunctions]: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

