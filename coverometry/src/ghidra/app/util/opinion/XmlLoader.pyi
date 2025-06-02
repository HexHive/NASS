from typing import List
import ghidra.app.util
import ghidra.app.util.bin
import ghidra.app.util.importer
import ghidra.app.util.opinion
import ghidra.framework.model
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.util.task
import java.lang
import java.util


class XmlLoader(ghidra.app.util.opinion.AbstractProgramLoader):
    XML_SRC_NAME: unicode = u'XML Input Format'



    def __init__(self): ...



    @overload
    def compareTo(self, __a0: ghidra.app.util.opinion.Loader) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def equals(self, __a0: object) -> bool: ...

    def findSupportedLoadSpecs(self, provider: ghidra.app.util.bin.ByteProvider) -> java.util.Collection: ...

    def getClass(self) -> java.lang.Class: ...

    def getDefaultOptions(self, provider: ghidra.app.util.bin.ByteProvider, loadSpec: ghidra.app.util.opinion.LoadSpec, domainObject: ghidra.framework.model.DomainObject, loadIntoProgram: bool) -> List[ghidra.app.util.Option]: ...

    def getName(self) -> unicode: ...

    def getPreferredFileName(self, provider: ghidra.app.util.bin.ByteProvider) -> unicode: ...

    def getTier(self) -> ghidra.app.util.opinion.LoaderTier: ...

    def getTierPriority(self) -> int: ...

    def hashCode(self) -> int: ...

    def load(self, __a0: ghidra.app.util.bin.ByteProvider, __a1: unicode, __a2: ghidra.framework.model.Project, __a3: unicode, __a4: ghidra.app.util.opinion.LoadSpec, __a5: List[object], __a6: ghidra.app.util.importer.MessageLog, __a7: object, __a8: ghidra.util.task.TaskMonitor) -> ghidra.app.util.opinion.LoadResults: ...

    def loadInto(self, __a0: ghidra.app.util.bin.ByteProvider, __a1: ghidra.app.util.opinion.LoadSpec, __a2: List[object], __a3: ghidra.app.util.importer.MessageLog, __a4: ghidra.program.model.listing.Program, __a5: ghidra.util.task.TaskMonitor) -> None: ...

    def loadsIntoNewFolder(self) -> bool: ...

    @staticmethod
    def markAsFunction(program: ghidra.program.model.listing.Program, name: unicode, funcStart: ghidra.program.model.address.Address) -> None:
        """
        Mark this address as a function by creating a one byte function.  The single byte body
         function is picked up by the function analyzer, disassembled, and the body fixed.
         Marking the function this way keeps disassembly and follow on analysis out of the loaders.
        @param program the program
        @param name name of function, null if name not known
        @param funcStart starting address of the function
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def setProgramProperties(prog: ghidra.program.model.listing.Program, provider: ghidra.app.util.bin.ByteProvider, executableFormatName: unicode) -> None:
        """
        Sets a program's Executable Path, Executable Format, MD5, SHA256, and FSRL properties.
         <p>
        @param prog {@link Program} (with active transaction)
        @param provider {@link ByteProvider} that the program was created from
        @param executableFormatName executable format string
        @throws IOException if error reading from ByteProvider
        """
        ...

    @overload
    def supportsLoadIntoProgram(self) -> bool: ...

    @overload
    def supportsLoadIntoProgram(self, __a0: ghidra.program.model.listing.Program) -> bool: ...

    def toString(self) -> unicode: ...

    def validateOptions(self, __a0: ghidra.app.util.bin.ByteProvider, __a1: ghidra.app.util.opinion.LoadSpec, __a2: List[object], __a3: ghidra.program.model.listing.Program) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def name(self) -> unicode: ...

    @property
    def tier(self) -> ghidra.app.util.opinion.LoaderTier: ...

    @property
    def tierPriority(self) -> int: ...