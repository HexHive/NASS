from typing import List
import java.io
import java.lang


class LEB128(object):
    """
    Logic for reading LEB128 values.
 
     LEB128 is a variable length integer encoding that uses 7 bits per byte, with the high bit
     being reserved as a continuation flag, with the least significant bytes coming first 
     (Little Endian Base 128).
 
     This implementation only supports reading values that decode to at most 64 bits (to fit into
     a java long).
 
     When reading a value, you must already know if it was written as a signed or unsigned value to
     be able to decode it correctly.
    """

    MAX_SUPPORTED_LENGTH: int = 10



    def __init__(self): ...



    @staticmethod
    def decode(bytes: List[int], offset: int, isSigned: bool) -> long:
        """
        Decodes a LEB128 number from a byte array and returns it as a long.
         <p>
         See {@link #read(InputStream, boolean)}
        @param bytes the bytes representing the LEB128 number
        @param offset offset in byte array of where to start reading bytes
        @param isSigned true if the value is signed
        @return long integer value.  Caller must treat it as unsigned if isSigned parameter was
        	       set to false
        @throws IOException if array offset is invalid, decoded value is outside the range of a java
         64 bit int (or it used more than {@value #MAX_SUPPORTED_LENGTH} bytes to be encoded), or 
         the end of the array was reached before reaching the end of the encoded value
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getLength(is_: java.io.InputStream) -> int:
        """
        Returns the length of the variable length LEB128 value.
        @param is InputStream to get bytes from
        @return length of the LEB128 value, or -1 if the end of the value is not found
        @throws IOException if error getting next byte from stream
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def read(is_: java.io.InputStream, isSigned: bool) -> long:
        """
        Reads a LEB128 number from the stream and returns it as a java 64 bit long int.
         <p>
         Large unsigned integers that use all 64 bits are returned in a java native
         'long' type, which is signed.  It is up to the caller to treat the value as unsigned.
         <p>
         Large integers that use more than 64 bits will cause an IOException to be thrown.
         <p>
        @param is {@link InputStream} to get bytes from
        @param isSigned true if the value is signed
        @return long integer value.  Caller must treat it as unsigned if isSigned parameter was
         set to false
        @throws IOException if an I/O error occurs or decoded value is outside the range of a java
         64 bit int (or it used more than {@value #MAX_SUPPORTED_LENGTH} bytes to be encoded), or 
         there is an error or EOF getting a byte from the InputStream before reaching the end of the
         encoded value
        """
        ...

    @staticmethod
    def signed(is_: java.io.InputStream) -> long:
        """
        Reads a signed LEB128 variable length integer from the stream.
        @param is {@link InputStream} to get bytes from
        @return leb128 value, as a long
        @throws IOException if an I/O error occurs or decoded value is outside the range of a java
         64 bit int (or it used more than {@value #MAX_SUPPORTED_LENGTH} bytes to be encoded), or 
         there is an error or EOF getting a byte from the InputStream before reaching the end of the
         encoded value
        """
        ...

    def toString(self) -> unicode: ...

    @staticmethod
    def unsigned(is_: java.io.InputStream) -> long:
        """
        Reads an unsigned LEB128 variable length integer from the stream.
        @param is {@link InputStream} to get bytes from
        @return leb128 value, as a long
        @throws IOException if an I/O error occurs or decoded value is outside the range of a java
         64 bit int (or it used more than {@value #MAX_SUPPORTED_LENGTH} bytes to be encoded), or 
         there is an error or EOF getting a byte from the InputStream before reaching the end of the
         encoded value
        """
        ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

