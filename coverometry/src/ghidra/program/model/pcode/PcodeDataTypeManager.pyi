import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.program.model.pcode
import ghidra.program.model.symbol
import java.lang


class PcodeDataTypeManager(object):
    """
    Class for marshaling DataType objects to and from the Decompiler.
    """





    def __init__(self, prog: ghidra.program.model.listing.Program, simplifier: ghidra.program.model.symbol.NameTransformer): ...



    def clearTemporaryIds(self) -> None:
        """
        Throw out any temporary ids (from previous function decompilation) and
         reset the counter.
        """
        ...

    def decodeDataType(self, decoder: ghidra.program.model.pcode.Decoder) -> ghidra.program.model.data.DataType:
        """
        Decode a data-type from the stream
        @param decoder is the stream decoder
        @return the decoded data-type object
        @throws DecoderException for invalid encodings
        """
        ...

    def encodeCompositeZeroSizePlaceholder(self, encoder: ghidra.program.model.pcode.Encoder, type: ghidra.program.model.data.DataType) -> None:
        """
        Encode a Structure to the stream that has its size reported as zero.
        @param encoder is the stream encoder
        @param type data type to encode
        @throws IOException for errors in the underlying stream
        """
        ...

    def encodeCoreTypes(self, encoder: ghidra.program.model.pcode.Encoder) -> None:
        """
        Encode the coretypes to the stream
        @param encoder is the stream encoder
        @throws IOException for errors in the underlying stream
        """
        ...

    def encodeType(self, encoder: ghidra.program.model.pcode.Encoder, type: ghidra.program.model.data.DataType, size: int) -> None:
        """
        Encode information for a data-type to the stream
        @param encoder is the stream encoder
        @param type is the data-type to encode
        @param size is the size of the data-type
        @throws IOException for errors in the underlying stream
        """
        ...

    def encodeTypeRef(self, encoder: ghidra.program.model.pcode.Encoder, type: ghidra.program.model.data.DataType, size: int) -> None:
        """
        Encode a reference to the given data-type to stream. Most data-types produce a
         {@code <type>} element, fully describing the data-type. Where possible a {@code <typeref>}
         element is produced, which just encodes the name of the data-type, deferring a full
         description of the data-type. For certain simple or nameless data-types, a {@code <type>}
         element is emitted giving a full description.
        @param encoder is the stream encoder
        @param type is the data-type to be converted
        @param size is the size in bytes of the specific instance of the data-type
        @throws IOException for errors in the underlying stream
        """
        ...

    def encodeUnion(self, encoder: ghidra.program.model.pcode.Encoder, unionType: ghidra.program.model.data.Union) -> None:
        """
        Encode a Union data-type to the stream
        @param encoder is the stream encoder
        @param unionType is the Union data-type
        @throws IOException for errors in the underlying stream
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def findBaseType(self, nm: unicode, id: long) -> ghidra.program.model.data.DataType:
        """
        Find a base/built-in data-type with the given name and/or id.  If an id is provided and
         a corresponding data-type exists, this data-type is returned. Otherwise the first
         built-in data-type with a matching name is returned
        @param nm name of data-type
        @param id is an optional data-type id number
        @return the data-type object or null if no matching data-type exists
        """
        ...

    @staticmethod
    def findPointerRelativeInner(base: ghidra.program.model.data.DataType, offset: int) -> ghidra.program.model.data.DataType:
        """
        Get the inner data-type being referred to by an offset from a relative/shifted pointer.
         Generally we expect the base of the relative pointer to be a structure and the offset
         refers to a (possibly nested) field. In this case, we return the data-type of the field.
         Otherwise return an "undefined" data-type.
        @param base is the base data-type of the relative pointer
        @param offset is the offset into the base data-type
        @return the inner data-type
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getNameTransformer(self) -> ghidra.program.model.symbol.NameTransformer: ...

    def getProgram(self) -> ghidra.program.model.listing.Program: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setNameTransformer(self, newTransformer: ghidra.program.model.symbol.NameTransformer) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def nameTransformer(self) -> ghidra.program.model.symbol.NameTransformer: ...

    @nameTransformer.setter
    def nameTransformer(self, value: ghidra.program.model.symbol.NameTransformer) -> None: ...

    @property
    def program(self) -> ghidra.program.model.listing.Program: ...