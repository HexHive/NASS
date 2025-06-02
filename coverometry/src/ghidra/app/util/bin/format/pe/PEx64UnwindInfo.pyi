from typing import List
import ghidra.app.util.bin
import ghidra.app.util.bin.format.pe
import ghidra.program.model.data
import java.lang
import java.util


class PEx64UnwindInfo(object, ghidra.app.util.bin.StructConverter):





    class UNWIND_CODE_OPCODE(java.lang.Enum):
        UWOP_ALLOC_LARGE: ghidra.app.util.bin.format.pe.PEx64UnwindInfo.UNWIND_CODE_OPCODE = UWOP_ALLOC_LARGE
        UWOP_ALLOC_SMALL: ghidra.app.util.bin.format.pe.PEx64UnwindInfo.UNWIND_CODE_OPCODE = UWOP_ALLOC_SMALL
        UWOP_PUSH_MACHFRAME: ghidra.app.util.bin.format.pe.PEx64UnwindInfo.UNWIND_CODE_OPCODE = UWOP_PUSH_MACHFRAME
        UWOP_PUSH_NONVOL: ghidra.app.util.bin.format.pe.PEx64UnwindInfo.UNWIND_CODE_OPCODE = UWOP_PUSH_NONVOL
        UWOP_SAVE_NONVOL: ghidra.app.util.bin.format.pe.PEx64UnwindInfo.UNWIND_CODE_OPCODE = UWOP_SAVE_NONVOL
        UWOP_SAVE_NONVOL_FAR: ghidra.app.util.bin.format.pe.PEx64UnwindInfo.UNWIND_CODE_OPCODE = UWOP_SAVE_NONVOL_FAR
        UWOP_SAVE_XMM: ghidra.app.util.bin.format.pe.PEx64UnwindInfo.UNWIND_CODE_OPCODE = UWOP_SAVE_XMM
        UWOP_SAVE_XMM128: ghidra.app.util.bin.format.pe.PEx64UnwindInfo.UNWIND_CODE_OPCODE = UWOP_SAVE_XMM128
        UWOP_SAVE_XMM128_FAR: ghidra.app.util.bin.format.pe.PEx64UnwindInfo.UNWIND_CODE_OPCODE = UWOP_SAVE_XMM128_FAR
        UWOP_SAVE_XMM_FAR: ghidra.app.util.bin.format.pe.PEx64UnwindInfo.UNWIND_CODE_OPCODE = UWOP_SAVE_XMM_FAR
        UWOP_SET_FPREG: ghidra.app.util.bin.format.pe.PEx64UnwindInfo.UNWIND_CODE_OPCODE = UWOP_SET_FPREG







        @overload
        def compareTo(self, __a0: java.lang.Enum) -> int: ...

        @overload
        def compareTo(self, __a0: object) -> int: ...

        def describeConstable(self) -> java.util.Optional: ...

        def equals(self, __a0: object) -> bool: ...

        @staticmethod
        def fromInt(__a0: int) -> ghidra.app.util.bin.format.pe.PEx64UnwindInfo.UNWIND_CODE_OPCODE: ...

        def getClass(self) -> java.lang.Class: ...

        def getDeclaringClass(self) -> java.lang.Class: ...

        def hashCode(self) -> int: ...

        def id(self) -> int: ...

        def name(self) -> unicode: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def ordinal(self) -> int: ...

        def toString(self) -> unicode: ...

        @overload
        @staticmethod
        def valueOf(__a0: unicode) -> ghidra.app.util.bin.format.pe.PEx64UnwindInfo.UNWIND_CODE_OPCODE: ...

        @overload
        @staticmethod
        def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

        @staticmethod
        def values() -> List[ghidra.app.util.bin.format.pe.PEx64UnwindInfo.UNWIND_CODE_OPCODE]: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...







    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toDataType(self) -> ghidra.program.model.data.DataType: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

