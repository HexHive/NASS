from typing import List
import ghidra.app.util.bin.format.dwarf4.attribs
import ghidra.program.model.scalar
import java.lang


class DWARFNumericAttribute(ghidra.program.model.scalar.Scalar, ghidra.app.util.bin.format.dwarf4.attribs.DWARFAttributeValue):
    """
    DWARF numeric attribute.
    """





    @overload
    def __init__(self, value: long):
        """
        Creates a new numeric value, using 64 bits and marked as signed
        @param value long 64 bit value
        """
        ...

    @overload
    def __init__(self, bitLength: int, value: long, signed: bool):
        """
        Creates a new numeric value, using the specific bitLength and value.
        @param bitLength number of bits, valid values are 1..64, or 0 if value is also 0
        @param value value of the scalar, any bits that are set above bitLength will be ignored
        @param signed true for a signed value, false for an unsigned value.
        """
        ...

    @overload
    def __init__(self, bitLength: int, value: long, signed: bool, ambiguous: bool):
        """
        Creates a new numeric value, using the specific bitLength and value.
        @param bitLength number of bits, valid values are 1..64, or 0 if value is also 0
        @param value value of the scalar, any bits that are set above bitLength will be ignored
        @param signed true for a signed value, false for an unsigned value.
        @param ambiguous true for value with ambiguous signedness ({@code signed} parameter should
         not be trusted), false for value where the {@code signed} parameter is known to be correct
        """
        ...



    def bitLength(self) -> int:
        """
        <p>The size of this Scalar in bits.  This is constant for a
         Scalar.  It is not dependent on the particular value of the scalar.
         For example, a 16-bit Scalar should always return 16 regardless of the
         actual value held.</p>
        @return the width of this Scalar.
        """
        ...

    def byteArrayValue(self) -> List[int]:
        """
        <p>Returns a byte array representing this Scalar.  The size of
         the byte array is the number of bytes required to hold the
         number of bits returned by <CODE>bitLength()</CODE>.</p>
        @return a big-endian byte array containing the bits in this Scalar.
        """
        ...

    def equals(self, obj: object) -> bool: ...

    def getBigInteger(self) -> long:
        """
        Returns the BigInteger representation of the value.
        @return new BigInteger representation of the value
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getSignedValue(self) -> long:
        """
        Get the value as a signed long, where the highest bit of the value, if set, will be 
         extended to fill the remaining bits of a java long.
        @return signed value
        """
        ...

    def getUnsignedValue(self) -> long:
        """
        Get the value as an unsigned long.
        @return unsigned value
        """
        ...

    @overload
    def getValue(self) -> long:
        """
        Returns the value in its preferred signed-ness.  See {@link #getSignedValue()} and
         {@link #getUnsignedValue()}.
        @return value, as either signed or unsigned, depending on how this instance was created
        """
        ...

    @overload
    def getValue(self, signednessOverride: bool) -> long:
        """
        {@return the value, using the specified signedness.  Equivalent to calling getSignedValue()
         or getUnsignedValue()}
        @param signednessOverride true for a signed value, false for an unsigned value
        """
        ...

    def getValueWithSignednessHint(self, signednessHint: bool) -> long:
        """
        {@return the value, forcing the signedness of ambiguous values using the specified hint}
        @param signednessHint true to default to a signed value, false to default to an 
         unsigned value
        """
        ...

    def hashCode(self) -> int: ...

    def isAmbiguousSignedness(self) -> bool:
        """
        {@return boolean flag, if true this value's signedness is up to the user of the value,
         if false the signedness was determined when the value was constructed}
        """
        ...

    def isSigned(self) -> bool:
        """
        Returns true if scalar was created as a signed value
        @return boolean true if this scalar was created as a signed value, false if was created as
         unsigned
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def testBit(self, n: int) -> bool:
        """
        <p>Returns true if and only if the designated bit is set to one.
         Computes ((this &amp; (1&lt;&lt;n)) != 0).  Bits are numbered
         0..bitlength()-1 with 0 being the least significant bit.</p>
        @param n the bit to test.
        @return true if and only if the designated bit is set to one.
        @throws IndexOutOfBoundsException if n &gt;= bitLength().
        """
        ...

    @overload
    def toString(self) -> unicode: ...

    @overload
    def toString(self, radix: int, zeroPadded: bool, showSign: bool, pre: unicode, post: unicode) -> unicode:
        """
        <p>Get a String representing this Scalar using the
         format defined by radix.</p>
        @param radix an integer base to use in representing the number
          (only 2, 8, 10, 16 are valid).  If 10 is specified, all
          remaining parameters are ignored.
        @param zeroPadded a boolean which if true will have the
          number left padded with 0 to the width necessary to hold
          the maximum value.
        @param showSign if true the '-' sign will be prepended for negative values, else
         value will be treated as an unsigned value and output without a sign.
        @param pre a String to append after the sign (if signed) but before
          the digits.
        @param post a String to append after the digits.
        @return a String representation of this scalar.
        @throws IllegalArgumentException If radix is not valid.
        """
        ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def ambiguousSignedness(self) -> bool: ...