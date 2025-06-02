import ghidra.program.model.symbol
import java.lang


class IllegalCharCppTransformer(object, ghidra.program.model.symbol.NameTransformer):
    """
    Replace illegal characters in the given name with '_'.  The transformer treats the name as a
     C++ symbol. Letters and digits are generally legal. '~' is allowed at the start of the symbol.
     Template parameters, surrounded by '' and '', allow additional special characters. 
     Certain special characters are allowed after the keyword "operator".
    """





    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def simplify(self, input: unicode) -> unicode: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

