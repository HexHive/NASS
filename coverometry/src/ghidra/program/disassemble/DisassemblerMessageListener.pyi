import java.lang


class DisassemblerMessageListener(object):
    """
    Interface for reporting disassembly messages
    """

    CONSOLE: ghidra.program.disassemble.DisassemblerMessageListener = ghidra.program.disassemble.DisassemblerMessageListener$2@2d600636
    IGNORE: ghidra.program.disassemble.DisassemblerMessageListener = ghidra.program.disassemble.DisassemblerMessageListener$1@45803d75







    def disassembleMessageReported(self, msg: unicode) -> None:
        """
        Method called to display disassembly progress messasges
        @param msg the message to display.
        """
        ...

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

