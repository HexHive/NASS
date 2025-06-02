import ghidra.app.util.bin
import java.lang


class LEB128Info(object):
    """
    Class to hold result of reading a LEB128 value, along with size and position metadata.
    """









    def asInt32(self) -> int:
        """
        Returns the value as an signed int32.  If the actual value
         is outside the range of a java int (ie.  {@link Integer#MIN_VALUE}.. {@link Integer#MAX_VALUE}),
         an exception is thrown.
        @return int in the range of {@link Integer#MIN_VALUE} to  {@link Integer#MAX_VALUE}
        @throws IOException if value is outside range
        """
        ...

    def asLong(self) -> long:
        """
        Returns the value as a 64bit primitive long.  Interpreting the signed-ness of the
         value will depend on the way the value was read (ie. if {@link #signed(BinaryReader)}
         vs. {@link #unsigned(BinaryReader)} was used).
        @return long value.
        """
        ...

    def asUInt32(self) -> int:
        """
        Returns the value as an unsigned int32.  If the actual value
         is outside the positive range of a java int (ie. 0.. {@link Integer#MAX_VALUE}),
         an exception is thrown.
        @return int in the range of 0 to  {@link Integer#MAX_VALUE}
        @throws IOException if value is outside range
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getLength(self) -> int:
        """
        Returns the number of bytes that were used to store the LEB128 value in the stream
         it was read from.
        @return number of bytes used to store the read LEB128 value
        """
        ...

    def getOffset(self) -> long:
        """
        Returns the offset of the LEB128 value in the stream it was read from.
        @return stream offset of the LEB128 value
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def readValue(reader: ghidra.app.util.bin.BinaryReader, isSigned: bool) -> ghidra.app.util.bin.LEB128Info:
        """
        Reads a LEB128 value from the BinaryReader and returns a {@link LEB128Info} instance
         that contains the value along with size and position metadata.
         <p>
        @param reader {@link BinaryReader} to read bytes from
        @param isSigned true if the value is signed
        @return a {@link LEB128Info} instance with the read LEB128 value with metadata
        @throws IOException if an I/O error occurs or value is outside the range of a java
         64 bit int
        """
        ...

    @staticmethod
    def signed(reader: ghidra.app.util.bin.BinaryReader) -> ghidra.app.util.bin.LEB128Info:
        """
        Reads an signed LEB128 value from the BinaryReader and returns a {@link LEB128Info} instance
         that contains the value along with size and position metadata.
         <p>
        @param reader {@link BinaryReader} to read bytes from
        @return a {@link LEB128Info} instance with the read LEB128 value with metadata
        @throws IOException if an I/O error occurs or value is outside the range of a java
         64 bit int
        """
        ...

    def toString(self) -> unicode: ...

    @staticmethod
    def unsigned(reader: ghidra.app.util.bin.BinaryReader) -> ghidra.app.util.bin.LEB128Info:
        """
        Reads an unsigned LEB128 value from the BinaryReader and returns a {@link LEB128Info} instance
         that contains the value along with size and position metadata.
         <p>
        @param reader {@link BinaryReader} to read bytes from
        @return a {@link LEB128Info} instance with the read LEB128 value with metadata
        @throws IOException if an I/O error occurs or value is outside the range of a java
         64 bit int
        """
        ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def length(self) -> int: ...

    @property
    def offset(self) -> long: ...