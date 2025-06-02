import ghidra.app.plugin.exceptionhandlers.gcc
import java.lang


class DwarfDecoderFactory(object):
    """
    Generate instances of DwarfEHDecoder suitable for various pointer-encodings.
    """





    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getDecoder(mode: int) -> ghidra.app.plugin.exceptionhandlers.gcc.DwarfEHDecoder:
        """
        Get the appropriate decoder for the given 8-bit mode; mode is parsed into
         decode format, application mode, and indirection flag.
        @see #createDecoder(DwarfEHDataDecodeFormat, DwarfEHDataApplicationMode, boolean)
        @param mode a byte that indicates an encoding
        @return the decoder for the indicated mode of encoding
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

