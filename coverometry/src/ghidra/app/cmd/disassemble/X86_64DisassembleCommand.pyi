import ghidra.app.cmd.disassemble
import ghidra.framework.model
import ghidra.program.disassemble
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.util.task
import java.lang


class X86_64DisassembleCommand(ghidra.app.cmd.disassemble.DisassembleCommand):
    """
    Command object for performing 64-/32-bit x86 disassembly
 
 
     This generally only comes up when debugging, since there can be multiple images loaded by an
     x86-64 target. For WoW64, the images may be mixed. Thus, this command allows you to disassemble
     64-bit or 32-bit instructions whenever the language is set to 64-bit x86.
 
 
     WARNING: If used in static programs, i.e., not debug traces, there are some potential
     remaining issues, particularly dealing with stored context and follow-on disassembly -- typically
     called for by the analyzers. In most cases, this does not matter, since mixed 64- and 32-bit code
     in a single image is likely a niche case and can be handled via careful commands from the user.
     Nevertheless, TODO: Rework x86-64 analyzers to call the correct mode of disassembly.
    """





    @overload
    def __init__(self, start: ghidra.program.model.address.Address, restrictedSet: ghidra.program.model.address.AddressSetView, size32Mode: bool):
        """
        Constructor for X86_64DisassembleCommand.
        @param start address to be the start of a disassembly.
        @param restrictedSet addresses that can be disassembled. a null set implies no restrictions.
        @param size32Mode pass true if disassembling in 32-bit compatibility mode, otherwise normal
                    64-bit disassembly will be performed.
        """
        ...

    @overload
    def __init__(self, startSet: ghidra.program.model.address.AddressSetView, restrictedSet: ghidra.program.model.address.AddressSetView, size32Mode: bool):
        """
        Constructor for X86_64DisassembleCommand.
        @param startSet set of addresses to be the start of disassembly. The Command object will
                    attempt to start a disassembly at each address in this set.
        @param restrictedSet addresses that can be disassembled. a null set implies no restrictions.
        @param size32Mode pass true if disassembling in 32-bit compatibility mode, otherwise normal
                    64-bit disassembly will be performed.
        """
        ...



    @staticmethod
    def alignSet(alignment: int, set: ghidra.program.model.address.AddressSetView) -> ghidra.program.model.address.AddressSet: ...

    @overload
    def applyTo(self, obj: ghidra.framework.model.DomainObject) -> bool: ...

    @overload
    def applyTo(self, obj: ghidra.framework.model.DomainObject, monitor: ghidra.util.task.TaskMonitor) -> bool: ...

    def canCancel(self) -> bool:
        """
        Check if the command can be canceled.
        @return true if this command can be canceled
        """
        ...

    def dispose(self) -> None:
        """
        Called when this command is going to be removed/canceled without
         running it.  This gives the command the opportunity to free any
         temporary resources it has hold of.
        """
        ...

    def enableCodeAnalysis(self, enable: bool) -> None:
        """
        Set code analysis enablement. By default new instructions will be submitted for
         auto-analysis.
        @param enable
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDisassembledAddressSet(self) -> ghidra.program.model.address.AddressSet:
        """
        Returns an address set of all instructions that were disassembled.
        @return an address set of all instructions that were disassembled
        """
        ...

    def getName(self) -> unicode: ...

    def getStatusMsg(self) -> unicode: ...

    def hasProgress(self) -> bool:
        """
        Check if the command provides progress information.
        @return true if the command shows progress information
        """
        ...

    def hashCode(self) -> int: ...

    def isModal(self) -> bool:
        """
        Check if the command requires the monitor to be modal.  No other
         command should be allowed, and the GUI will be locked.
        @return true if no other operation should be going on while this
         command is in progress.
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setInitialContext(self, initialContextValue: ghidra.program.model.lang.RegisterValue) -> None: ...

    def setSeedContext(self, seedContext: ghidra.program.disassemble.DisassemblerContextImpl) -> None: ...

    def taskCompleted(self) -> None:
        """
        Called when the task monitor is completely done with indicating progress.
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
    def initialContext(self) -> None: ...  # No getter available.

    @initialContext.setter
    def initialContext(self, value: ghidra.program.model.lang.RegisterValue) -> None: ...

    @property
    def name(self) -> unicode: ...

    @property
    def seedContext(self) -> None: ...  # No getter available.

    @seedContext.setter
    def seedContext(self, value: ghidra.program.disassemble.DisassemblerContextImpl) -> None: ...