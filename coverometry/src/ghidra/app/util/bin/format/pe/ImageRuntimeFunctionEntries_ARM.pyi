import ghidra.app.util.bin.format.pe
import ghidra.program.model.address
import ghidra.program.model.listing
import java.lang


class ImageRuntimeFunctionEntries_ARM(object, ghidra.app.util.bin.format.pe.ImageRuntimeFunctionEntries):
    """

     typedef struct _IMAGE_ARM_RUNTIME_FUNCTION_ENTRY {
       DWORD BeginAddress;
       union {
         DWORD UnwindData;
         struct {
           DWORD Flag : 2;
           DWORD FunctionLength : 11;
           DWORD Ret : 2;
           DWORD H : 1;
           DWORD Reg : 3;
           DWORD R : 1;
           DWORD L : 1;
           DWORD C : 1;
           DWORD StackAdjust : 10;
         } DUMMYSTRUCTNAME;
       } DUMMYUNIONNAME;
     } IMAGE_ARM_RUNTIME_FUNCTION_ENTRY, * PIMAGE_ARM_RUNTIME_FUNCTION_ENTRY;
 
    """









    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def markup(self, program: ghidra.program.model.listing.Program, headerStart: ghidra.program.model.address.Address) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

