import ghidra.app.util.bin.format.macho
import ghidra.program.model.address
import ghidra.program.model.listing
import java.lang


class MachoRelocation(object):
    """
    A representation of a single Mach-O relocation that the MachoRelocationHandler will use
     to perform the relocation.  In Mach-O, some relocations may be "paired," so an instance of this
     class may contain 2 RelocationInfos.
    """





    @overload
    def __init__(self, program: ghidra.program.model.listing.Program, machoHeader: ghidra.app.util.bin.format.macho.MachHeader, relocationAddress: ghidra.program.model.address.Address, relocationInfo: ghidra.app.util.bin.format.macho.RelocationInfo):
        """
        Creates a new unpaired {@link MachoRelocation} object
        @param program The program
        @param machoHeader The Mach-O header
        @param relocationAddress The {@link Address} the relocation takes place at
        @param relocationInfo The lower-level {@link RelocationInfo} that describes the relocation
        """
        ...

    @overload
    def __init__(self, program: ghidra.program.model.listing.Program, machoHeader: ghidra.app.util.bin.format.macho.MachHeader, relocationAddress: ghidra.program.model.address.Address, relocationInfo: ghidra.app.util.bin.format.macho.RelocationInfo, relocationInfoExtra: ghidra.app.util.bin.format.macho.RelocationInfo):
        """
        Creates a new paired {@link MachoRelocation} object
        @param program The program
        @param machoHeader The Mach-O header
        @param relocationAddress The {@link Address} the relocation takes place at
        @param relocationInfo The lower-level {@link RelocationInfo} that describes the first part
           of the relocation
        @param relocationInfoExtra The lower-level {@link RelocationInfo} that describes the second
           part of the relocation
        """
        ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Gets the {@link Program} associated with this relocation
        @return The {@link Program} associated with this relocation
        """
        ...

    def getRelocationAddress(self) -> ghidra.program.model.address.Address:
        """
        Gets the {@link Address} the relocation takes place at
        @return The {@link Address} the relocation takes place at
        """
        ...

    def getRelocationInfo(self) -> ghidra.app.util.bin.format.macho.RelocationInfo:
        """
        Gets the lower-level {@link RelocationInfo} that describes the relocation
        @return The lower-level {@link RelocationInfo} that describes the relocation
        """
        ...

    def getRelocationInfoExtra(self) -> ghidra.app.util.bin.format.macho.RelocationInfo:
        """
        Gets the lower-level {@link RelocationInfo} that describes the second part of the paired 
         relocation.  This could be null if the relocation is not paired.
        @return The lower-level {@link RelocationInfo} that describes the second part of the paired 
           relocation, or null if the relocation is not paired
        """
        ...

    def getTargetAddress(self) -> ghidra.program.model.address.Address:
        """
        Gets the {@link Address} of the relocation target
        @return The {@link Address} of the relocation target
        @throws RelocationException If the {@link Address} of the relocation target could not be found
        """
        ...

    def getTargetAddressExtra(self) -> ghidra.program.model.address.Address:
        """
        Gets the {@link Address} of the extra relocation target
        @return The {@link Address} of the extra relocation target
        @throws RelocationException If the {@link Address} of the extra relocation target could not be 
           found (of if there wasn't an extra relocation target).
        """
        ...

    def getTargetDescription(self) -> unicode:
        """
        Gets a short description of the target of the relocation
        @return A short description of the target of the relocation
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def requiresRelocation(self) -> bool:
        """
        Checks to see if this relocation requires work to be done on it. Since our
         {@link MachoLoader loader} does not allow non-default image bases, it is unnecessary to 
         perform relocations under certain conditions.
        @return True if relocation steps are needed; otherwise, false
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
    def program(self) -> ghidra.program.model.listing.Program: ...

    @property
    def relocationAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def relocationInfo(self) -> ghidra.app.util.bin.format.macho.RelocationInfo: ...

    @property
    def relocationInfoExtra(self) -> ghidra.app.util.bin.format.macho.RelocationInfo: ...

    @property
    def targetAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def targetAddressExtra(self) -> ghidra.program.model.address.Address: ...

    @property
    def targetDescription(self) -> unicode: ...