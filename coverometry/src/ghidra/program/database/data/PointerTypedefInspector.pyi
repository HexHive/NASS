import ghidra.program.model.address
import ghidra.program.model.data
import java.lang


class PointerTypedefInspector(object):
    """
    PointerTypeDefInspector provides utilities for inspecting Pointer - TypeDefs.  
     These special typedefs allow a modified-pointer datatype to be used for special situations where
     a simple pointer will not suffice and special stored pointer interpretation/handling is required.  
 
     The various Pointer modifiers on the associated TypeDef are achieved through the use of various
     TypeDefSettingsDefinition.  The PointerTypedefBuilder may be used to simplify the creation
     of these pointer-typedefs.
    """









    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getPointerAddressSpace(pointerTypeDef: ghidra.program.model.data.TypeDef, addrFactory: ghidra.program.model.address.AddressFactory) -> ghidra.program.model.address.AddressSpace:
        """
        Determine the referenced address space for specified pointerTypeDef based upon
         its default settings.
        @param pointerTypeDef Pointer TypeDef
        @param addrFactory target address factory
        @return referenced address space or null if not specified or address space
         lookup fails.
        """
        ...

    @staticmethod
    def getPointerBitMask(pointerTypeDef: ghidra.program.model.data.TypeDef) -> long:
        """
        Determine the pointer bit-mask for the specified pointerTypeDef based upon
         its default settings. If specified, bit-mask will be AND-ed with stored 
         offset prior to any specified bit-shift.
        @param pointerTypeDef Pointer TypeDef
        @return pointer bit-shift or 0 if unspecified or not applicable
        """
        ...

    @staticmethod
    def getPointerBitShift(pointerTypeDef: ghidra.program.model.data.TypeDef) -> long:
        """
        Determine the pointer bit-shift for the specified pointerTypeDef based upon
         its default settings. A right-shift is specified by a positive value while
         a left-shift is specified by a negative value.
         If specified, bit-shift will be applied after applying any specified bit-mask.
        @param pointerTypeDef Pointer TypeDef
        @return pointer bit-shift or 0 if unspecified or not applicable
        """
        ...

    @staticmethod
    def getPointerComponentOffset(pointerTypeDef: ghidra.program.model.data.TypeDef) -> long:
        """
        Determine the component-offset for the specified pointerTypeDef based upon
         its default settings.
        @param pointerTypeDef Pointer TypeDef
        @return pointer component offset or 0 if unspecified or not applicable
        """
        ...

    @staticmethod
    def getPointerType(pointerTypeDef: ghidra.program.model.data.TypeDef) -> ghidra.program.model.data.PointerType:
        """
        Get the pointer type (see {@link PointerType}).
        @param pointerTypeDef Pointer TypeDef
        @return pointer type or null if not a pointer
        """
        ...

    @staticmethod
    def hasPointerBitMask(pointerTypeDef: ghidra.program.model.data.TypeDef) -> bool:
        """
        Determine if the specified pointerTypeDef has a pointer bit-mask specified.
        @param pointerTypeDef Pointer TypeDef
        @return true if a bit-mask setting exists, else false
        """
        ...

    @staticmethod
    def hasPointerBitShift(pointerTypeDef: ghidra.program.model.data.TypeDef) -> bool:
        """
        Determine if the specified pointerTypeDef has a pointer bit-shift specified.
        @param pointerTypeDef Pointer TypeDef
        @return true if non-zero bit-shift setting exists, else false
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

