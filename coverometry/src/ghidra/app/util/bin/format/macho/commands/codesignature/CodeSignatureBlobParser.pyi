import ghidra.app.util.bin
import ghidra.app.util.bin.format.macho.commands.codesignature
import java.lang


class CodeSignatureBlobParser(object):
    """
    Class to parse Code Signature blobs
    """





    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def parse(reader: ghidra.app.util.bin.BinaryReader) -> ghidra.app.util.bin.format.macho.commands.codesignature.CodeSignatureGenericBlob:
        """
        Parses a new Code Signature blob
        @param reader A {@link BinaryReader} positioned at the start of a Code Signature blob
        @return A new Code Signature blob
        @throws IOException if there was an IO-related error parsing the blob
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

