from typing import List
import ghidra.app.util.bin.format.elf
import ghidra.app.util.bin.format.elf.info
import ghidra.util.classfinder
import ghidra.util.task
import java.lang


class ElfInfoProducer(ghidra.util.classfinder.ExtensionPoint, object):
    """
    Something that adds nice-to-have markup and program info to Elf binaries.
 
     Classes that implement this ExtensionPoint must have names that end with "ElfInfoProducer" for
     the class searcher to find them.
 
     Instances are created for each Elf binary that is being loaded.
    """









    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getElfInfoProducers(elfLoadHelper: ghidra.app.util.bin.format.elf.ElfLoadHelper) -> List[ghidra.app.util.bin.format.elf.info.ElfInfoProducer]:
        """
        Returns a sorted list of new and initialized ElfInfoProducer instances.
        @param elfLoadHelper {@link ElfLoadHelper} with contents of file being loaded
        @return List of ElfInfoProducers
        """
        ...

    def hashCode(self) -> int: ...

    def init(self, elfLoadHelper: ghidra.app.util.bin.format.elf.ElfLoadHelper) -> None:
        """
        Initializes this instance.
        @param elfLoadHelper the Elf binary
        """
        ...

    def markupElfInfo(self, monitor: ghidra.util.task.TaskMonitor) -> None:
        """
        Called by the Elf loader to give this ElfInfoProducer the opportunity to markup the Elf
         binary.
        @param monitor {@link TaskMonitor}
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

