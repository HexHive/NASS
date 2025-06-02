import ghidra.program.model.address
import ghidra.program.model.data
import java.lang


class PointerTypedefBuilder(object):
    """
    PointerTypedefBuilder provides a builder for creating Pointer - TypeDefs.  
     These special typedefs allow a modified-pointer datatype to be used for special situations where
     a simple pointer will not suffice and special stored pointer interpretation/handling is required.  
 
     This builder simplifies the specification of various Pointer modifiers during the 
     construction of an associated TypeDef.
 
     A convenience method Pointer#typedefBuilder() also exists for creating a builder
     from a pointer instance.  In addition the utility class PointerTypedefInspector
     can be used to easily determine pointer-typedef settings.
    """





    @overload
    def __init__(self, pointerDataType: ghidra.program.model.data.Pointer, dtm: ghidra.program.model.data.DataTypeManager):
        """
        Construct a {@link Pointer} - {@link TypeDef} builder.
        @param pointerDataType base pointer datatype (required)
        @param dtm datatype manager (highly recommended although may be null)
        """
        ...

    @overload
    def __init__(self, baseDataType: ghidra.program.model.data.DataType, pointerSize: int, dtm: ghidra.program.model.data.DataTypeManager):
        """
        Construct a {@link Pointer} - {@link TypeDef} builder.
        @param baseDataType baseDataType or null to use a default pointer
        @param pointerSize pointer size or -1 to use default pointer size for specified datatype manager.
        @param dtm datatype manager (highly recommended although may be null)
        """
        ...



    @overload
    def addressSpace(self, spaceName: unicode) -> ghidra.program.model.data.PointerTypedefBuilder:
        """
        Update pointer referenced address space when translating to an absolute memory offset.
        @param spaceName pointer referenced address space or null for default space
        @return this builder
        """
        ...

    @overload
    def addressSpace(self, space: ghidra.program.model.address.AddressSpace) -> ghidra.program.model.data.PointerTypedefBuilder:
        """
        Update pointer referenced address space when translating to an absolute memory offset.
        @param space pointer referenced address space or null for default space
        @return this builder
        """
        ...

    def bitMask(self, unsignedMask: long) -> ghidra.program.model.data.PointerTypedefBuilder:
        """
        Update pointer offset bit-mask when translating to an absolute memory offset.
         If specified, bit-mask will be AND-ed with stored offset prior to any 
         specified bit-shift.
        @param unsignedMask unsigned bit-mask
        @return this builder
        """
        ...

    def bitShift(self, shift: int) -> ghidra.program.model.data.PointerTypedefBuilder:
        """
        Update pointer offset bit-shift when translating to an absolute memory offset.
         If specified, bit-shift will be applied after applying any specified bit-mask.
        @param shift bit-shift (right: positive, left: negative)
        @return this builder
        """
        ...

    def build(self) -> ghidra.program.model.data.TypeDef:
        """
        Build pointer-typedef with specified settings.
        @return unresolved pointer typedef
        """
        ...

    def componentOffset(self, offset: long) -> ghidra.program.model.data.PointerTypedefBuilder:
        """
        Update pointer relative component-offset.  This setting is interpretted in two
         ways: 
         <ul>
         <li>The specified offset is considered to be relative to the start of the base datatype
         (e.g., structure).  It may refer to a component-offset within the base datatype or outside of 
         it.</li>
         <li>When pointer-typedef is initially applied to memory, an {@link OffsetReference} will be produced
         by subtracting the component-offset from the stored pointer offset to determine the 
         base-offset for the reference.  While the xref will be to the actual referenced location, the
         reference markup will be shown as <i>&lt;base&gt;+&lt;offset&gt;</i></li>
         </ul>
        @param offset component offset relative to a base-offset and associated base-datatype
        @return this builder
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def name(self, name: unicode) -> ghidra.program.model.data.PointerTypedefBuilder:
        """
        Set pointer-typedef name.  If not specified a default name will be generated based 
         upon the associated pointer type and the specified settings.
        @param name typedef name
        @return this builder
        @throws InvalidNameException if name contains unsupported characters
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    def type(self, type: ghidra.program.model.data.PointerType) -> ghidra.program.model.data.PointerTypedefBuilder:
        """
        Update pointer type.
        @param type pointer type
        @return this builder
        """
        ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

