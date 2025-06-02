from typing import List
import ghidra.app.util.bin.format.golang
import ghidra.program.model.data
import ghidra.program.model.listing
import java.lang


class GoFunctionFixup(object):
    """
    Utility class to fix Golang function parameter storage
    """





    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    @overload
    @staticmethod
    def fixupFunction(func: ghidra.program.model.listing.Function) -> None:
        """
        Assigns custom storage for a function's parameters, using the function's current
         parameter list (formal info only) as starting information.
        @param func Ghidra {@link Function} to fix
        @throws DuplicateNameException if invalid parameter names
        @throws InvalidInputException if invalid data types or storage
        """
        ...

    @overload
    @staticmethod
    def fixupFunction(func: ghidra.program.model.listing.Function, goVersion: ghidra.app.util.bin.format.golang.GoVer) -> None:
        """
        Assigns custom storage for a function's parameters, using the function's current
         parameter list (formal info only) as starting information.
        @param func Ghidra {@link Function} to fix
        @param goVersion {@link GoVer} enum
        @throws DuplicateNameException if invalid parameter names
        @throws InvalidInputException if invalid data types or storage
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def isGolangAbi0Func(func: ghidra.program.model.listing.Function) -> bool: ...

    @staticmethod
    def isInLocalVarStorageArea(func: ghidra.program.model.listing.Function, stackOffset: long) -> bool: ...

    @staticmethod
    def makeEmptyArrayDataType(dt: ghidra.program.model.data.DataType) -> ghidra.program.model.data.DataType:
        """
        Returns a Ghidra data type that represents a zero-length array, to be used as a replacement
         for a zero-length array parameter.
        @param dt data type that will donate its name to the created empty array type
        @return {@link DataType} that represents a specific zero-length array type
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def reverseNonStackStorageLocations(__a0: List[object]) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

