import ghidra.program.model.lang
import java.lang
import java.util


class LanguageUtilities(object):








    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def getAllPairsForLanguage(__a0: ghidra.program.model.lang.LanguageID) -> java.util.Set: ...

    @staticmethod
    def getAllPairsForLanguages(__a0: java.util.Set) -> java.util.Set: ...

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

