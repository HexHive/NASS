from typing import List
import generic.stl
import ghidra.program.model.data
import java.lang
import java.util


class DataTypeDependencyOrderer(object):





    class Entry(object):




        def __init__(self): ...



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



    @overload
    def __init__(self, dtManager: ghidra.program.model.data.DataTypeManager):
        """
        This constructor starts with an empty DataType list, which can be added to.
        @param dtManager the manager used to extract IDs
        """
        ...

    @overload
    def __init__(self, __a0: ghidra.program.model.data.DataTypeManager, __a1: java.util.ArrayList): ...



    def addType(self, dataType: ghidra.program.model.data.DataType) -> None:
        """
        This method adds a single DataTypes to the input DataType list and
          marks the data as dirty (all must need recalculated).
        @param dataType A single DataType to add to the input DataType list.
        """
        ...

    def addTypeList(self, __a0: java.util.ArrayList) -> None: ...

    def clear(self) -> None:
        """
        This method clears the input DataType list and
          marks the data as dirty (all must need recalculated).
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getAcyclicDependencyLists(self) -> generic.stl.Pair:
        """
        This method returns two lists:
         1) is the set of structs/unions. Intended for outputting zero-sized definitions.
         2) is the acyclic dependency list (broken at composites and pointers to composites)
         This works (and the dependency graph is able to be broken of cycles) because
         composites can be given zero size to start with and then later updated with full size.
        @return pair of arrayLists--one of composites and one complete list of dependents
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getCompositeList(self) -> List[ghidra.program.model.data.DataType]:
        """
        This method returns the ArrayList of structs/unions
        @return An arrayList of Composite
        """
        ...

    def getDependencyList(self) -> List[ghidra.program.model.data.DataType]:
        """
        This returns the acyclic dependency list (broken at composites and pointers to composites)
        @return An ArrayList of dependents.
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def removeType(self, dataType: ghidra.program.model.data.DataType) -> None:
        """
        This method removes a DataType from the list and
          marks the data as dirty (all must need recalculated).
        @param dataType The DataType to remove from the input list
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def acyclicDependencyLists(self) -> generic.stl.Pair: ...

    @property
    def compositeList(self) -> java.util.ArrayList: ...

    @property
    def dependencyList(self) -> java.util.ArrayList: ...