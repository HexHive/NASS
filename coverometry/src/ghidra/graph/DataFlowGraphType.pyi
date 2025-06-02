from typing import List
import ghidra.graph
import ghidra.program.model.symbol
import java.lang


class DataFlowGraphType(ghidra.graph.ProgramGraphType):




    def __init__(self): ...



    def containsEdgeType(self, edgeType: unicode) -> bool:
        """
        Test if the given string is a valid edge type
        @param edgeType the string to test for being a valid edge type
        @return true if the given string is a valid edge type
        """
        ...

    def containsVertexType(self, vertexType: unicode) -> bool:
        """
        Test if the given string is a valid vertex type
        @param vertexType the string to test for being a valid vertex type
        @return true if the given string is a valid vertex type
        """
        ...

    def equals(self, obj: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDescription(self) -> unicode:
        """
        Returns a description for this type of graph
        @return a description for this type of graph
        """
        ...

    @staticmethod
    def getEdgeType(refType: ghidra.program.model.symbol.RefType) -> unicode: ...

    def getEdgeTypes(self) -> List[unicode]:
        """
        Returns a list of valid edge types for graphs of this type
        @return a list of valid edge types for graphs of this type
        """
        ...

    def getName(self) -> unicode:
        """
        Returns a name for this type of graph
        @return a name of this type of graph
        """
        ...

    def getOptionsName(self) -> unicode: ...

    def getVertexTypes(self) -> List[unicode]:
        """
        Returns a list of valid vertex types for graphs of this type
        @return a list of valid vertex types for graphs of this type
        """
        ...

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

