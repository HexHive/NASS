import ghidra.pcode.floatformat
import java.lang
import java.math


class FloatFormat(object):
    """
    FloatFormat provides IEEE 754 floating-point encoding formats in support of
     floating-point data types and floating-point emulation.  A combination of Java 
     float/double and BigFloat are used to facilitate floating-point operations.
    """

    maxValue: ghidra.pcode.floatformat.BigFloat
    minValue: ghidra.pcode.floatformat.BigFloat







    @overload
    def decodeBigFloat(self, encoding: long) -> ghidra.pcode.floatformat.BigFloat:
        """
        Decode {@code encoding} to a BigFloat using this format.
 
         The method {@link #decodeBigFloat(BigInteger)} should be used for encodings 
         larger than 8 bytes.
        @param encoding the encoding
        @return the decoded value as a BigFloat
        """
        ...

    @overload
    def decodeBigFloat(self, encoding: long) -> ghidra.pcode.floatformat.BigFloat:
        """
        Decode {@code encoding} to a BigFloat using this format.
 
         The method {@link #decodeBigFloat(BigInteger)} should be used for encodings 
         larger than 8 bytes.
        @param encoding the encoding
        @return the decoded value as a BigFloat
        """
        ...

    def decodeHostFloat(self, encoding: long) -> float: ...

    def equals(self, __a0: object) -> bool: ...

    @overload
    def getBigFloat(self, f: float) -> ghidra.pcode.floatformat.BigFloat: ...

    @overload
    def getBigFloat(self, f: float) -> ghidra.pcode.floatformat.BigFloat: ...

    @overload
    def getBigFloat(self, string: unicode) -> ghidra.pcode.floatformat.BigFloat:
        """
        Constructs a {@code BigFloat} initialized to the value
         represented by the specified decimal {@code String}, as performed
         by {@link BigDecimal#BigDecimal(String)}.  Other values permitted
         are (case-insenstive): "NaN", "Infinity", "+Infinity", "-Infinity"
         (See {@link BigFloat#NAN}, {@link BigFloat#INFINITY}, {@link BigFloat#POSITIVE_INFINITY}, 
         {@link BigFloat#NEGATIVE_INFINITY}).
        @param string the string to be parsed.
        @return value as a {@link BigFloat}
        @throws NullPointerException if the string is null
        @throws NumberFormatException if the string parse fails.
        """
        ...

    @overload
    def getBigFloat(self, value: java.math.BigDecimal) -> ghidra.pcode.floatformat.BigFloat:
        """
        Constructs a {@code BigFloat} initialized to the value
         represented by the specified {@code BigDecimal}.
        @param value the decimal value.
        @return value as a {@link BigFloat}
        @throws NullPointerException if the string is null
        @throws NumberFormatException if the string parse fails.
        """
        ...

    @overload
    def getBigFloat(self, value: long) -> ghidra.pcode.floatformat.BigFloat: ...

    def getBigInfinity(self, sgn: bool) -> ghidra.pcode.floatformat.BigFloat: ...

    def getBigInfinityEncoding(self, sgn: bool) -> long: ...

    def getBigNaN(self, sgn: bool) -> ghidra.pcode.floatformat.BigFloat: ...

    def getBigNaNEncoding(self, sgn: bool) -> long: ...

    def getBigZero(self, sgn: bool) -> ghidra.pcode.floatformat.BigFloat: ...

    def getBigZeroEncoding(self, sgn: bool) -> long: ...

    def getClass(self) -> java.lang.Class: ...

    @overload
    def getEncoding(self, host: float) -> long: ...

    @overload
    def getEncoding(self, value: ghidra.pcode.floatformat.BigFloat) -> long: ...

    def getInfinityEncoding(self, sgn: bool) -> long: ...

    def getMaxBigFloat(self) -> ghidra.pcode.floatformat.BigFloat:
        """
        Get the maximum finite {@link BigFloat} value for this format
        @return maximum finite {@link BigFloat} value
        """
        ...

    def getMinBigFloat(self) -> ghidra.pcode.floatformat.BigFloat:
        """
        Get the minimum finite subnormal {@link BigFloat} value for this format
        @return minimum finite subnormal {@link BigFloat} value
        """
        ...

    def getNaNEncoding(self, sgn: bool) -> long: ...

    def getSize(self) -> int: ...

    def getZeroEncoding(self, sgn: bool) -> long: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @overload
    def opAbs(self, a: long) -> long: ...

    @overload
    def opAbs(self, a: long) -> long: ...

    @overload
    def opAdd(self, a: long, b: long) -> long: ...

    @overload
    def opAdd(self, a: long, b: long) -> long: ...

    @overload
    def opCeil(self, a: long) -> long: ...

    @overload
    def opCeil(self, a: long) -> long: ...

    @overload
    def opDiv(self, a: long, b: long) -> long: ...

    @overload
    def opDiv(self, a: long, b: long) -> long: ...

    @overload
    def opEqual(self, a: long, b: long) -> long: ...

    @overload
    def opEqual(self, a: long, b: long) -> long: ...

    @overload
    def opFloat2Float(self, a: long, outformat: ghidra.pcode.floatformat.FloatFormat) -> long: ...

    @overload
    def opFloat2Float(self, a: long, outformat: ghidra.pcode.floatformat.FloatFormat) -> long: ...

    @overload
    def opFloor(self, a: long) -> long: ...

    @overload
    def opFloor(self, a: long) -> long: ...

    @overload
    def opInt2Float(self, a: long, sizein: int) -> long: ...

    @overload
    def opInt2Float(self, a: long, sizein: int, signed: bool) -> long: ...

    @overload
    def opLess(self, a: long, b: long) -> long: ...

    @overload
    def opLess(self, a: long, b: long) -> long: ...

    @overload
    def opLessEqual(self, a: long, b: long) -> long: ...

    @overload
    def opLessEqual(self, a: long, b: long) -> long: ...

    @overload
    def opMult(self, a: long, b: long) -> long: ...

    @overload
    def opMult(self, a: long, b: long) -> long: ...

    @overload
    def opNan(self, a: long) -> long: ...

    @overload
    def opNan(self, a: long) -> long: ...

    @overload
    def opNeg(self, a: long) -> long: ...

    @overload
    def opNeg(self, a: long) -> long: ...

    @overload
    def opNotEqual(self, a: long, b: long) -> long: ...

    @overload
    def opNotEqual(self, a: long, b: long) -> long: ...

    @overload
    def opRound(self, a: long) -> long: ...

    @overload
    def opRound(self, a: long) -> long: ...

    @overload
    def opSqrt(self, a: long) -> long: ...

    @overload
    def opSqrt(self, a: long) -> long: ...

    @overload
    def opSub(self, a: long, b: long) -> long: ...

    @overload
    def opSub(self, a: long, b: long) -> long: ...

    @overload
    def opTrunc(self, a: long, sizeout: int) -> long: ...

    @overload
    def opTrunc(self, a: long, sizeout: int) -> long: ...

    def round(self, bigFloat: ghidra.pcode.floatformat.BigFloat) -> java.math.BigDecimal:
        """
        Round {@code bigFloat} using this format's displayContext.
        @param bigFloat any BigFloat
        @return a BigDecimal rounded according to this format's displayContext
        """
        ...

    @overload
    @staticmethod
    def toBigFloat(f: float) -> ghidra.pcode.floatformat.BigFloat:
        """
        Convert a native float to {@link BigFloat} using 4-byte IEEE 754 encoding
        @param f a float
        @return {@link BigFloat} equal to {@code f}
        """
        ...

    @overload
    @staticmethod
    def toBigFloat(f: float) -> ghidra.pcode.floatformat.BigFloat:
        """
        Convert a native float to {@link BigFloat} using 4-byte IEEE 754 encoding
        @param f a float
        @return {@link BigFloat} equal to {@code f}
        """
        ...

    @overload
    def toDecimalString(self, bigFloat: ghidra.pcode.floatformat.BigFloat) -> unicode:
        """
        Perform appropriate rounding and conversion to BigDecimal prior to generating
         a formatted decimal string of the specified BigFloat value.
        @param bigFloat value
        @return decimal string representation
        """
        ...

    @overload
    def toDecimalString(self, bigFloat: ghidra.pcode.floatformat.BigFloat, compact: bool) -> unicode:
        """
        Perform appropriate rounding and conversion to BigDecimal prior to generating
         a formatted decimal string of the specified BigFloat value.
        @param bigFloat value
        @param compact if true the precision will be reduced to a form which is still equivalent at
         the binary encoding level for this format.  Enabling this will incur additional overhead.
        @return decimal string representation
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
    def maxBigFloat(self) -> ghidra.pcode.floatformat.BigFloat: ...

    @property
    def minBigFloat(self) -> ghidra.pcode.floatformat.BigFloat: ...

    @property
    def size(self) -> int: ...