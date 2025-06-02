from typing import List
import ghidra.program.model.symbol
import ghidra.service.graph
import java.lang


class ProgramGraphType(ghidra.service.graph.GraphType):
    """
    Defines a common set of vertex and edge types GraphType for program code and data flow
     graphs. Each specific type of program graph will use a subclass to specifically identify the
     graph type.
    """

    BAD: unicode = u'Bad'
    BODY: unicode = u'Body'
    CALLOTHER_OVERRIDE_CALL: unicode = u'Call Override Unconditional'
    CALLOTHER_OVERRIDE_JUMP: unicode = u'Call Override Unconditional'
    CALL_OVERRIDE_UNCONDITIONAL: unicode = u'Call Override Unconditional'
    COMPUTED_CALL: unicode = u'Computed Call'
    COMPUTED_CALL_TERMINATOR: unicode = u'Computed Call Terminator'
    COMPUTED_JUMP: unicode = u'Computed Jump'
    CONDITIONAL_CALL: unicode = u'Conditional Call'
    CONDITIONAL_CALL_TERMINATOR: unicode = u'Conditional Call Terminator'
    CONDITIONAL_COMPUTED_CALL: unicode = u'Conditional Computed Call'
    CONDITIONAL_COMPUTED_JUMP: unicode = u'Conditional Computed Jump'
    CONDITIONAL_JUMP: unicode = u'Conditional Jump'
    CONDITIONAL_TERMINATOR: unicode = u'Conditional Terminator'
    DATA: unicode = u'Data'
    DATA_INDIRECT: unicode = u'Data Ind'
    ENTRY: unicode = u'Entry'
    ENTRY_EDGE: unicode = u'Entry'
    ENTRY_NEXUS: unicode = u'Entry-Nexus'
    EXIT: unicode = u'Exit'
    EXTERNAL: unicode = u'External'
    EXTERNAL_REF: unicode = u'External'
    FALL_THROUGH: unicode = u'Fall Through'
    INDIRECTION: unicode = u'Indirection'
    INSTRUCTION: unicode = u'Instruction'
    JUMP_OVERRIDE_UNCONDITIONAL: unicode = u'Call Override Unconditional'
    JUMP_TERMINATOR: unicode = u'Jump Terminator'
    PARAM: unicode = u'Param'
    READ: unicode = u'Read'
    READ_INDIRECT: unicode = u'Read Ind'
    READ_WRITE: unicode = u'Read Write'
    READ_WRITE_INDIRECT: unicode = u'Read Write Ind'
    STACK: unicode = u'Stack'
    SWITCH: unicode = u'Switch'
    TERMINATOR: unicode = u'Terminator'
    THUNK: unicode = u'Thunk'
    UNCONDITIONAL_CALL: unicode = u'Unconditional Call'
    UNCONDITIONAL_JUMP: unicode = u'Unconditional Jump'
    UNKNOWN_DATA: unicode = u'Data'
    WRITE: unicode = u'Write'
    WRITE_INDIRECT: unicode = u'Write Ind'







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

    @property
    def optionsName(self) -> unicode: ...