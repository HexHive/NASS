import ghidra.app.util.bin.format.dwarf4
import java.lang


class DWARFLine(object):





    class DWARFFile(object):




        @overload
        def __init__(self, __a0: ghidra.app.util.bin.BinaryReader): ...

        @overload
        def __init__(self, __a0: unicode, __a1: long, __a2: long, __a3: long): ...



        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def getDirectoryIndex(self) -> long: ...

        def getModificationTime(self) -> long: ...

        def getName(self) -> unicode: ...

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
        def directoryIndex(self) -> long: ...

        @property
        def modificationTime(self) -> long: ...

        @property
        def name(self) -> unicode: ...





    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getFile(self, index: int, compileDirectory: unicode) -> unicode:
        """
        Get a file name given a file index.
        @param index index of the file
        @param compileDirectory current compile unit directory
        @return file name
        """
        ...

    def getFullFile(self, index: int, compileDirectory: unicode) -> unicode:
        """
        Get a file name with the full path included.
        @param index index of the file
        @param compileDirectory current compile unit directory
        @return file name with full path
        """
        ...

    def hashCode(self) -> int: ...

    def isValidFileIndex(self, index: int) -> bool:
        """
        Returns true if file exists.
        @param index file number, excluding 0
        @return boolean true if file exists
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def read(diea: ghidra.app.util.bin.format.dwarf4.DIEAggregate) -> ghidra.app.util.bin.format.dwarf4.DWARFLine:
        """
        Read a DWARFLine from the compile unit's DW_AT_stmt_list location in the 
         DebugLine stream (if present).
        @param diea {@link DIEAggregate} compile unit DIE(a)
        @return a new DWARFLine instance if DW_AT_stmt_list and stream are present, otherwise null
        @throws IOException if error reading data
        @throws DWARFException if bad DWARF values
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

