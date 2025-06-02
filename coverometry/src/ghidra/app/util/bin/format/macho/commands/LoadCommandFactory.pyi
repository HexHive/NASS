import ghidra.app.util.bin
import ghidra.app.util.bin.format.macho
import ghidra.app.util.bin.format.macho.commands
import ghidra.app.util.opinion.DyldCacheUtils
import java.lang


class LoadCommandFactory(object):
    """
    A factory used to create LoadCommands
    """





    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getLoadCommand(reader: ghidra.app.util.bin.BinaryReader, header: ghidra.app.util.bin.format.macho.MachHeader, splitDyldCache: ghidra.app.util.opinion.DyldCacheUtils.SplitDyldCache) -> ghidra.app.util.bin.format.macho.commands.LoadCommand:
        """
        Create and parses a {@link LoadCommand}
         <p>
         NOTE: Parsing {@link LoadCommand}s whose data lives in the __LINKEDIT segment require that
         the __LINKEDIT {@link SegmentCommand} have already been parsed.  Thus, it is required that
         this method be called on {@link SegmentCommand}s before other types of {@link LoadCommand}s.
        @param reader A {@link BinaryReader reader} that points to the start of the load command
        @param header The {@link MachHeader header} associated with this load command
        @param splitDyldCache The {@link SplitDyldCache} that this header resides in.  Could be null
           if a split DYLD cache is not being used.
        @return A new {@link LoadCommand}
        @throws IOException if an IO-related error occurs while parsing
        @throws MachException if the load command is invalid
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

