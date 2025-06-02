import ghidra.program.database.reloc
import java.lang


class RelocationDBAdapterV6(ghidra.program.database.reloc.RelocationDBAdapter):
    """
    Relocation Adapter (v6) introduced a stored status and length value.  The byte-length value
     is  only stored/used when stored bytes are not used and the original bytes are obtained from 
     the underlying FileBytes via associated Memory.  Older program's may 
     have a stored bytes array but is unneccessary when original FileBytes are available. 
 
     During the transition of older relocation records we are unable to determine a proper status 
     without comparing current memory to the original bytes.  It may also be neccessary to reconcile
     overlapping relocations when the stored bytes value is null to obtain a valid length.  This
     transition is too complicated for a low-level record translation so it must be deferred to 
     a higher-level program upgrade (see ProgramDB).  This also holds true for establishing
     a reasonable status for existing relocation records.  During the initial record migration a
     status of Status#UNKNOWN and default length will be used.  After the program is 
     ready another high-level upgrade, based on Program version, will then attempt to refine these 
     records further.
    """









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

