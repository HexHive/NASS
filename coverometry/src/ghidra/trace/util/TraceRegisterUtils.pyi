from typing import List
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.trace.model.guest
import ghidra.trace.model.listing
import ghidra.trace.model.memory
import ghidra.trace.util
import java.lang
import java.nio
import java.util


class TraceRegisterUtils(java.lang.Enum):








    @staticmethod
    def bufferForValue(__a0: ghidra.program.model.lang.Register, __a1: ghidra.program.model.lang.RegisterValue) -> java.nio.ByteBuffer: ...

    @staticmethod
    def combineWithTraceBaseRegisterValue(__a0: ghidra.program.model.lang.RegisterValue, __a1: ghidra.trace.model.guest.TracePlatform, __a2: long, __a3: ghidra.trace.model.memory.TraceMemorySpace, __a4: bool) -> ghidra.program.model.lang.RegisterValue: ...

    @staticmethod
    def combineWithTraceParentRegisterValue(__a0: ghidra.program.model.lang.Register, __a1: ghidra.program.model.lang.RegisterValue, __a2: ghidra.trace.model.guest.TracePlatform, __a3: long, __a4: ghidra.trace.model.memory.TraceMemorySpace, __a5: bool) -> ghidra.program.model.lang.RegisterValue: ...

    @overload
    def compareTo(self, __a0: java.lang.Enum) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    @overload
    @staticmethod
    def computeMaskOffset(__a0: ghidra.program.model.lang.Register) -> int: ...

    @overload
    @staticmethod
    def computeMaskOffset(__a0: ghidra.program.model.lang.RegisterValue) -> int: ...

    def describeConstable(self) -> java.util.Optional: ...

    @staticmethod
    def encodeValueRepresentationHackPointer(__a0: ghidra.program.model.lang.Register, __a1: ghidra.trace.model.listing.TraceData, __a2: unicode) -> ghidra.program.model.lang.RegisterValue: ...

    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def finishBuffer(__a0: java.nio.ByteBuffer, __a1: ghidra.program.model.lang.Register) -> ghidra.program.model.lang.RegisterValue: ...

    def getClass(self) -> java.lang.Class: ...

    def getDeclaringClass(self) -> java.lang.Class: ...

    @staticmethod
    def getOverlayRange(__a0: ghidra.program.model.address.AddressSpace, __a1: ghidra.program.model.address.AddressRange) -> ghidra.program.model.address.AddressRange: ...

    @staticmethod
    def getOverlaySet(__a0: ghidra.program.model.address.AddressSpace, __a1: ghidra.program.model.address.AddressSetView) -> ghidra.program.model.address.AddressSetView: ...

    @staticmethod
    def getPhysicalRange(__a0: ghidra.program.model.address.AddressRange) -> ghidra.program.model.address.AddressRange: ...

    @staticmethod
    def getPhysicalSet(__a0: ghidra.program.model.address.AddressSetView) -> ghidra.program.model.address.AddressSetView: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def isByteBound(__a0: ghidra.program.model.lang.Register) -> bool: ...

    def name(self) -> unicode: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def ordinal(self) -> int: ...

    @staticmethod
    def padOrTruncate(__a0: List[int], __a1: int) -> List[int]: ...

    @staticmethod
    def prepareBuffer(__a0: ghidra.program.model.lang.Register) -> java.nio.ByteBuffer: ...

    @staticmethod
    def rangeForRegister(__a0: ghidra.program.model.lang.Register) -> ghidra.program.model.address.AddressRange: ...

    @staticmethod
    def requireByteBound(__a0: ghidra.program.model.lang.Register) -> None: ...

    @overload
    @staticmethod
    def seekComponent(__a0: ghidra.trace.model.listing.TraceData, __a1: ghidra.program.model.address.AddressRange) -> ghidra.trace.model.listing.TraceData: ...

    @overload
    @staticmethod
    def seekComponent(__a0: ghidra.trace.model.listing.TraceData, __a1: ghidra.program.model.lang.Register) -> ghidra.trace.model.listing.TraceData: ...

    def toString(self) -> unicode: ...

    @overload
    @staticmethod
    def valueOf(__a0: unicode) -> ghidra.trace.util.TraceRegisterUtils: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.trace.util.TraceRegisterUtils]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

