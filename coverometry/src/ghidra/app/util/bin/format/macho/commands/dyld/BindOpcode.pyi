from typing import List
import ghidra.app.util.bin.format.macho.commands.dyld
import ghidra.program.model.data
import java.lang
import java.util


class BindOpcode(java.lang.Enum):
    BIND_OPCODE_ADD_ADDR_ULEB: ghidra.app.util.bin.format.macho.commands.dyld.BindOpcode = BIND_OPCODE_ADD_ADDR_ULEB
    BIND_OPCODE_DONE: ghidra.app.util.bin.format.macho.commands.dyld.BindOpcode = BIND_OPCODE_DONE
    BIND_OPCODE_DO_BIND: ghidra.app.util.bin.format.macho.commands.dyld.BindOpcode = BIND_OPCODE_DO_BIND
    BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED: ghidra.app.util.bin.format.macho.commands.dyld.BindOpcode = BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED
    BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: ghidra.app.util.bin.format.macho.commands.dyld.BindOpcode = BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB
    BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: ghidra.app.util.bin.format.macho.commands.dyld.BindOpcode = BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB
    BIND_OPCODE_SET_ADDEND_SLEB: ghidra.app.util.bin.format.macho.commands.dyld.BindOpcode = BIND_OPCODE_SET_ADDEND_SLEB
    BIND_OPCODE_SET_DYLIB_ORDINAL_IMM: ghidra.app.util.bin.format.macho.commands.dyld.BindOpcode = BIND_OPCODE_SET_DYLIB_ORDINAL_IMM
    BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: ghidra.app.util.bin.format.macho.commands.dyld.BindOpcode = BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB
    BIND_OPCODE_SET_DYLIB_SPECIAL_IMM: ghidra.app.util.bin.format.macho.commands.dyld.BindOpcode = BIND_OPCODE_SET_DYLIB_SPECIAL_IMM
    BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: ghidra.app.util.bin.format.macho.commands.dyld.BindOpcode = BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB
    BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: ghidra.app.util.bin.format.macho.commands.dyld.BindOpcode = BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM
    BIND_OPCODE_SET_TYPE_IMM: ghidra.app.util.bin.format.macho.commands.dyld.BindOpcode = BIND_OPCODE_SET_TYPE_IMM
    BIND_OPCODE_THREADED: ghidra.app.util.bin.format.macho.commands.dyld.BindOpcode = BIND_OPCODE_THREADED







    @overload
    def compareTo(self, __a0: java.lang.Enum) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def describeConstable(self) -> java.util.Optional: ...

    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def forOpcode(__a0: int) -> ghidra.app.util.bin.format.macho.commands.dyld.BindOpcode: ...

    def getClass(self) -> java.lang.Class: ...

    def getDeclaringClass(self) -> java.lang.Class: ...

    def getOpcode(self) -> int: ...

    def hashCode(self) -> int: ...

    def name(self) -> unicode: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def ordinal(self) -> int: ...

    @staticmethod
    def toDataType() -> ghidra.program.model.data.DataType: ...

    def toString(self) -> unicode: ...

    @overload
    @staticmethod
    def valueOf(__a0: unicode) -> ghidra.app.util.bin.format.macho.commands.dyld.BindOpcode: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.app.util.bin.format.macho.commands.dyld.BindOpcode]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def opcode(self) -> int: ...