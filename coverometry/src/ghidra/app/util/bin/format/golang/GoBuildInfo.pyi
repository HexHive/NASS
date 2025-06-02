from typing import List
import ghidra.app.util.bin
import ghidra.app.util.bin.format.elf.info
import ghidra.app.util.bin.format.elf.info.ElfInfoItem
import ghidra.app.util.bin.format.golang
import ghidra.framework.options
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.listing
import java.io
import java.lang


class GoBuildInfo(object, ghidra.app.util.bin.format.elf.info.ElfInfoItem):
    """
    A program section that contains Go build information strings, namely go module package names,
     go module dependencies, and build/compiler flags, as well as the golang version itself.
    """

    SECTION_NAME: unicode = u'.go.buildinfo'







    def decorateProgramInfo(self, props: ghidra.framework.options.Options) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def findBuildInfo(program: ghidra.program.model.listing.Program) -> ghidra.app.util.bin.format.elf.info.ElfInfoItem.ItemWithAddress:
        """
        Searches for the GoBuildInfo structure in the most common and easy locations.
        @param program {@link Program} to search
        @return new {@link GoBuildInfo} instance, if present, null if missing or error
        """
        ...

    @staticmethod
    def fromProgram(program: ghidra.program.model.listing.Program) -> ghidra.app.util.bin.format.golang.GoBuildInfo:
        """
        Reads a GoBuildInfo ".go.buildinfo" section from the specified Program, if present.
        @param program {@link Program} that contains the ".go.buildinfo" section
        @return new {@link GoBuildInfo} instance, if present, null if missing or error
        """
        ...

    def getBuildSettings(self) -> List[ghidra.app.util.bin.format.golang.GoBuildSettings]: ...

    def getClass(self) -> java.lang.Class: ...

    def getDependencies(self) -> List[ghidra.app.util.bin.format.golang.GoModuleInfo]: ...

    def getEndian(self) -> ghidra.program.model.lang.Endian: ...

    def getModuleInfo(self) -> ghidra.app.util.bin.format.golang.GoModuleInfo: ...

    def getPath(self) -> unicode: ...

    def getPointerSize(self) -> int: ...

    def getVerEnum(self) -> ghidra.app.util.bin.format.golang.GoVer: ...

    def getVersion(self) -> unicode: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def isPresent(is_: java.io.InputStream) -> bool:
        """
        Probes the specified InputStream and returns true if it starts with a go buildinfo magic
         signature.
        @param is InputStream
        @return true if starts with buildinfo magic signature
        """
        ...

    @staticmethod
    def markupElfInfoItemSection(__a0: ghidra.program.model.listing.Program, __a1: unicode, __a2: ghidra.app.util.bin.format.elf.info.ElfInfoItem.ReaderFunc) -> None: ...

    def markupProgram(self, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def read(reader: ghidra.app.util.bin.BinaryReader, program: ghidra.program.model.listing.Program) -> ghidra.app.util.bin.format.golang.GoBuildInfo:
        """
        Reads a GoBuildInfo ".go.buildinfo" section from the specified stream.
        @param reader BinaryReader that contains the ".go.buildinfo" section
        @param program Program that contains the ".go.buildinfo" section
        @return new {@link GoBuildInfo} instance, never null
        @throws IOException if error reading or bad data
        """
        ...

    @staticmethod
    def readItemFromSection(__a0: ghidra.program.model.listing.Program, __a1: unicode, __a2: ghidra.app.util.bin.format.elf.info.ElfInfoItem.ReaderFunc) -> ghidra.app.util.bin.format.elf.info.ElfInfoItem.ItemWithAddress: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def buildSettings(self) -> List[object]: ...

    @property
    def dependencies(self) -> List[object]: ...

    @property
    def endian(self) -> ghidra.program.model.lang.Endian: ...

    @property
    def moduleInfo(self) -> ghidra.app.util.bin.format.golang.GoModuleInfo: ...

    @property
    def path(self) -> unicode: ...

    @property
    def pointerSize(self) -> int: ...

    @property
    def verEnum(self) -> ghidra.app.util.bin.format.golang.GoVer: ...

    @property
    def version(self) -> unicode: ...