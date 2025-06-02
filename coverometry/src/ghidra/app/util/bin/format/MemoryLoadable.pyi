import ghidra.app.util.bin.format.elf
import ghidra.program.model.address
import java.io
import java.lang
import java.util.function


class MemoryLoadable(object):
    """
    MemoryLoadable serves as both a marker interface which identifies a memory 
     loadable portion of a binary file (supports use as a Hashtable key).  In addition,
     it serves to supply the neccessary input stream to create a MemoryBlock.
    """









    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getFilteredLoadInputStream(self, elfLoadHelper: ghidra.app.util.bin.format.elf.ElfLoadHelper, start: ghidra.program.model.address.Address, dataLength: long, errorConsumer: java.util.function.BiConsumer) -> java.io.InputStream:
        """
        Return filtered InputStream for loading a memory block (includes non-loaded OTHER blocks).
         See {@link #hasFilteredLoadInputStream(ElfLoadHelper, Address)}.
        @param elfLoadHelper ELF load helper
        @param start memory load address
        @param dataLength the in-memory data length in bytes (actual bytes read from dataInput may be more)
        @param errorConsumer consumer that will accept errors which may occur during stream
         decompression, if null Msg.error() will be used.
        @return filtered input stream or original input stream
        @throws IOException if error initializing filtered input stream
        """
        ...

    def getRawInputStream(self) -> java.io.InputStream:
        """
        {@return raw data input stream associated with this loadable object.}
        @throws IOException if error initializing input stream
        """
        ...

    def hasFilteredLoadInputStream(self, elfLoadHelper: ghidra.app.util.bin.format.elf.ElfLoadHelper, start: ghidra.program.model.address.Address) -> bool:
        """
        Determine if the use of input stream decompression or filtering via an extension is neccessary. 
         If this method returns true and a 
         {@link #getFilteredLoadInputStream(ElfLoadHelper, Address, long, BiConsumer) filtered stream} 
         is required and will prevent the use of a direct mapping to file bytes for affected memory 
         regions.
        @param elfLoadHelper ELF load helper
        @param start memory load address
        @return true if the use of a filtered input stream is required
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

    @property
    def rawInputStream(self) -> java.io.InputStream: ...