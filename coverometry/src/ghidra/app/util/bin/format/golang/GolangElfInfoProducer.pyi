from typing import List
import ghidra.app.util.bin.format.elf
import ghidra.app.util.bin.format.elf.info
import ghidra.util.task
import java.lang


class GolangElfInfoProducer(object, ghidra.app.util.bin.format.elf.info.ElfInfoProducer):
    """
    Handles marking up and program info for Golang binaries.
 
 
     	NoteGoBuildId
     	GoBuildInfo
 	
     		Go version
     		App path, main package
     		Module dependency list
     		Build settings / flags
 	
 
    """





    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getElfInfoProducers(__a0: ghidra.app.util.bin.format.elf.ElfLoadHelper) -> List[object]: ...

    def hashCode(self) -> int: ...

    def init(self, elfLoadHelper: ghidra.app.util.bin.format.elf.ElfLoadHelper) -> None: ...

    def markupElfInfo(self, monitor: ghidra.util.task.TaskMonitor) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

