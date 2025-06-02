from typing import List
import ghidra.app.util.importer
import ghidra.program.model.listing
import ghidra.util.task
import java.lang


class ExternalSymbolResolver(object):




    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def fixUnresolvedExternalSymbols(__a0: List[object], __a1: bool, __a2: ghidra.app.util.importer.MessageLog, __a3: ghidra.util.task.TaskMonitor) -> None: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getLibrarySearchList(program: ghidra.program.model.listing.Program) -> List[ghidra.program.model.listing.Library]: ...

    @staticmethod
    def getRequiredLibraryProperty(libraryIndex: int) -> unicode:
        """
        Gets a program property name to represent the ordered required library of the given index
        @param libraryIndex The index of the required library
        @return A program property name to represent the ordered required library of the given index
        """
        ...

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

