import ghidra.program.model.address
import ghidra.program.model.lang
import java.lang


class ProgramArchitecture(object):
    """
    ProgramArchitecture which identifies program architecture details required to 
     utilize language/compiler-specific memory and variable storage specifications.
    """









    def equals(self, __a0: object) -> bool: ...

    def getAddressFactory(self) -> ghidra.program.model.address.AddressFactory:
        """
        Get the address factory for this architecture.  In the case of a {@link Program} this should 
         be the extended address factory that includes the stack space and any defined overlay
         spaces (i.e., {@link OverlayAddressSpace}).
        @return address factory
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getCompilerSpec(self) -> ghidra.program.model.lang.CompilerSpec:
        """
        Get the compiler specification
        @return compiler specification
        """
        ...

    def getLanguage(self) -> ghidra.program.model.lang.Language:
        """
        Get the processor language
        @return processor language
        """
        ...

    def getLanguageCompilerSpecPair(self) -> ghidra.program.model.lang.LanguageCompilerSpecPair:
        """
        Get the language/compiler spec ID pair associated with this program architecture.
        @return language/compiler spec ID pair
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

    @property
    def addressFactory(self) -> ghidra.program.model.address.AddressFactory: ...

    @property
    def compilerSpec(self) -> ghidra.program.model.lang.CompilerSpec: ...

    @property
    def language(self) -> ghidra.program.model.lang.Language: ...

    @property
    def languageCompilerSpecPair(self) -> ghidra.program.model.lang.LanguageCompilerSpecPair: ...