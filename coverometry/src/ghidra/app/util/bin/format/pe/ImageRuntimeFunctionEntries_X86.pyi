import ghidra.app.util.bin.format.pe
import ghidra.program.model.address
import ghidra.program.model.listing
import java.lang


class ImageRuntimeFunctionEntries_X86(object, ghidra.app.util.bin.format.pe.ImageRuntimeFunctionEntries):
    """

     typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY {
      DWORD BeginAddress;
      DWORD EndAddress;
      union {
        DWORD UnwindInfoAddress;
        DWORD UnwindData;
      } DUMMYUNIONNAME;
     } RUNTIME_FUNCTION, *PRUNTIME_FUNCTION, _IMAGE_RUNTIME_FUNCTION_ENTRY, *_PIMAGE_RUNTIME_FUNCTION_ENTRY;

     #define UNW_FLAG_NHANDLER 0x0
     #define UNW_FLAG_EHANDLER 0x1
     #define UNW_FLAG_UHANDLER 0x2
     #define UNW_FLAG_CHAININFO 0x4

     typedef struct _UNWIND_INFO {
         UCHAR Version : 3;
         UCHAR Flags : 5;
         UCHAR SizeOfProlog;
         UCHAR CountOfUnwindCodes;
         UCHAR FrameRegister : 4;
         UCHAR FrameOffset : 4;
         UNWIND_CODE UnwindCode[1];

     //
     // The unwind codes are followed by an optional DWORD aligned field that
     // contains the exception handler address or the address of chained unwind
     // information. If an exception handler address is specified, then it is
     // followed by the language specified exception handler data.
     //
     //  union {
     //      ULONG ExceptionHandler;
     //      ULONG FunctionEntry;
     //  };
     //
     //  ULONG ExceptionData[];
     //
     } UNWIND_INFO, *PUNWIND_INFO;
 
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

