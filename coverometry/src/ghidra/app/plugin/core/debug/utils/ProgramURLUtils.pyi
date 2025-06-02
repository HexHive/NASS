from typing import List
import ghidra.app.plugin.core.debug.utils
import ghidra.app.services
import ghidra.framework.model
import ghidra.program.model.listing
import java.lang
import java.net
import java.util


class ProgramURLUtils(java.lang.Enum):








    @overload
    def compareTo(self, __a0: java.lang.Enum) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def describeConstable(self) -> java.util.Optional: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDeclaringClass(self) -> java.lang.Class: ...

    @staticmethod
    def getDomainFileFromOpenProject(__a0: ghidra.framework.model.Project, __a1: java.net.URL) -> ghidra.framework.model.DomainFile: ...

    @staticmethod
    def getUrlFromProgram(__a0: ghidra.program.model.listing.Program) -> java.net.URL: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def isProjectDataURL(__a0: ghidra.framework.model.ProjectData, __a1: java.net.URL) -> bool: ...

    def name(self) -> unicode: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def openDomainFileFromOpenProject(__a0: ghidra.app.services.ProgramManager, __a1: ghidra.framework.model.Project, __a2: java.net.URL, __a3: int) -> ghidra.program.model.listing.Program: ...

    def ordinal(self) -> int: ...

    def toString(self) -> unicode: ...

    @overload
    @staticmethod
    def valueOf(__a0: unicode) -> ghidra.app.plugin.core.debug.utils.ProgramURLUtils: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.app.plugin.core.debug.utils.ProgramURLUtils]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

