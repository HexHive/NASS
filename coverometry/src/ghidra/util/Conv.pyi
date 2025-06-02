from typing import List
import java.lang


class Conv(object):
    """
    Helper methods for converting between
     number data types without negative
     promotion.
 
     Consider using java built-in methods for conversion instead of methods from this
     class.
    """

    BYTE_MASK: int = 255
    INT_MASK: long = 0xffffffffL
    SHORT_MASK: int = 65535







    @staticmethod
    def byteToInt(b: int) -> int:
        """
        Converts a byte to an integer.
        @param b the byte
        @return the integer equivalent of the byte
        @deprecated Use {@link Byte#toUnsignedInt(byte)} instead
        """
        ...

    @staticmethod
    def byteToLong(b: int) -> long:
        """
        Converts a byte to a long.
        @param b the byte
        @return the long equivalent of the byte
        @deprecated Use {@link Byte#toUnsignedLong(byte)} instead
        """
        ...

    @staticmethod
    def byteToShort(b: int) -> int:
        """
        @param b the byte
        @return the short equivalent of the byte
        @deprecated Use other built-ins like {@link Byte#toUnsignedInt(byte)}
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def intToLong(i: int) -> long:
        """
        Converts an integer to a long.
        @param i the integer
        @return the long equivalent of the long
        @deprecated Use {@link Integer#toUnsignedLong(int)} instead
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def shortToInt(s: int) -> int:
        """
        Converts a short to an integer.
        @param s the short
        @return the integer equivalent of the short
        @deprecated Use {@link Short#toUnsignedInt(short)} instead
        """
        ...

    @staticmethod
    def shortToLong(s: int) -> long:
        """
        Converts a short to a long.
        @param s the short
        @return the long eqivalent of the short
        @deprecated Use {@link Short#toUnsignedLong(short)} instead
        """
        ...

    @overload
    @staticmethod
    def toHexString(l: long) -> unicode:
        """
        Consider using {@link String#format(String, Object...) String.format("%016x", l)} instead.
         <p>
         Converts a long into a padded hex string.
        @param l the long
        @return the padded hex string
        """
        ...

    @overload
    @staticmethod
    def toHexString(b: int) -> unicode:
        """
        Consider using {@link String#format(String, Object...) String.format("%02x", b)} instead.
         <p>
         Converts a byte into a padded hex string.
        @param b the byte
        @return the padded hex string
        """
        ...

    @overload
    @staticmethod
    def toHexString(b: int) -> unicode:
        """
        Consider using {@link String#format(String, Object...) String.format("%02x", b)} instead.
         <p>
         Converts a byte into a padded hex string.
        @param b the byte
        @return the padded hex string
        """
        ...

    @overload
    @staticmethod
    def toHexString(b: int) -> unicode:
        """
        Consider using {@link String#format(String, Object...) String.format("%02x", b)} instead.
         <p>
         Converts a byte into a padded hex string.
        @param b the byte
        @return the padded hex string
        """
        ...

    @overload
    def toString(self) -> unicode: ...

    @overload
    @staticmethod
    def toString(array: List[int]) -> unicode:
        """
        <p>
         Old and <b>incorrect</b> way to convert bytes to a String by casting their
         values to chars.  Do not use.  Does not seem to be used in current codebase.
         <p>
        @param array
        @return 
        @deprecated Use {@link String#String(byte[], java.nio.charset.Charset) new String(bytes, StandardCharSets.US_ASCII)}
         instead
        """
        ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @staticmethod
    def zeropad(s: unicode, len: int) -> unicode:
        """
        Returns a string that is extended to length len with zeroes.
        @param s The string to pad
        @param len The length of the return string
        @return A string that has been left-padded with zeros to be of length len
        """
        ...

