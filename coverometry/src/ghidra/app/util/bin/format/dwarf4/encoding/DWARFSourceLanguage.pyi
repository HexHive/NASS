import java.lang


class DWARFSourceLanguage(object):
    """
    DWARF source lang consts from www.dwarfstd.org/doc/DWARF4.pdf.
 
     TODO: The PDF also lists the default lower bound for array dw_tag_subrange_type
     attributes based on this value.
    """

    DW_LANG_ALTIUM_Assembler: int = 37121
    DW_LANG_Ada83: int = 3
    DW_LANG_Ada95: int = 13
    DW_LANG_BLISS: int = 37
    DW_LANG_BORLAND_Delphi: int = 45056
    DW_LANG_C: int = 2
    DW_LANG_C11: int = 29
    DW_LANG_C89: int = 1
    DW_LANG_C99: int = 12
    DW_LANG_C_plus_plus: int = 4
    DW_LANG_C_plus_plus_03: int = 25
    DW_LANG_C_plus_plus_11: int = 26
    DW_LANG_C_plus_plus_14: int = 33
    DW_LANG_Cobol74: int = 5
    DW_LANG_Cobol85: int = 6
    DW_LANG_D: int = 19
    DW_LANG_Dylan: int = 32
    DW_LANG_Fortran03: int = 34
    DW_LANG_Fortran08: int = 35
    DW_LANG_Fortran77: int = 7
    DW_LANG_Fortran90: int = 8
    DW_LANG_Fortran95: int = 14
    DW_LANG_GOOGLE_RenderScript: int = 36439
    DW_LANG_Go: int = 22
    DW_LANG_Haskell: int = 24
    DW_LANG_Java: int = 11
    DW_LANG_Julia: int = 31
    DW_LANG_Mips_Assembler: int = 32769
    DW_LANG_Modula2: int = 10
    DW_LANG_Modula3: int = 23
    DW_LANG_OCaml: int = 27
    DW_LANG_ObjC: int = 16
    DW_LANG_ObjC_plus_plus: int = 17
    DW_LANG_OpenCL: int = 21
    DW_LANG_PL1: int = 15
    DW_LANG_Pascal83: int = 9
    DW_LANG_Python: int = 20
    DW_LANG_RenderScript: int = 36
    DW_LANG_Rust: int = 28
    DW_LANG_SUN_Assembler: int = 36865
    DW_LANG_Swift: int = 30
    DW_LANG_UPC: int = 18
    DW_LANG_hi_user: int = 65535
    DW_LANG_lo_user: int = 32768



    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

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

