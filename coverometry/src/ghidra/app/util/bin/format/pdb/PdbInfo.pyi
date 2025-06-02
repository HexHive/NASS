import ghidra.app.util.bin
import ghidra.app.util.bin.format.pdb
import ghidra.framework.options
import java.lang


class PdbInfo(object):
    """
    Bag of information about a Pdb symbol file, usually extracted from information present in a PE
     binary.
    """









    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def isValid(self) -> bool:
        """
        Returns true if this instance is valid.
        @return boolean true if valid (magic signature matches and fields have valid data)
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def read(reader: ghidra.app.util.bin.BinaryReader, offset: long) -> ghidra.app.util.bin.format.pdb.PdbInfo:
        """
        Read either a {@link PdbInfoCodeView} object or a {@link PdbInfoDotNet} object
         from the BinaryReader of a PE binary.
        @param reader BinaryReader
        @param offset position of the debug info
        @return new PdbInfoCodeView or PdbInfoDotNet object
        @throws IOException if error
        """
        ...

    def serializeToOptions(self, options: ghidra.framework.options.Options) -> None:
        """
        Writes the various PDB info fields to a program's options.
        @param options Options of a Program to write to
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def valid(self) -> bool: ...