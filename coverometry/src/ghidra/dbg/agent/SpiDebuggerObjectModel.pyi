from typing import List
import ghidra.dbg
import ghidra.dbg.target
import ghidra.dbg.target.schema
import ghidra.program.model.address
import java.lang
import java.util
import java.util.concurrent
import java.util.function


class SpiDebuggerObjectModel(ghidra.dbg.DebuggerObjectModel, object):
    ATTRIBUTE_MAP_TYPE: ghidra.async.TypeSpec = ghidra.async.TypeSpec$1@127e3bbb
    ELEMENT_MAP_TYPE: ghidra.async.TypeSpec = ghidra.async.TypeSpec$1@127e3bbb







    @overload
    def addModelListener(self, __a0: ghidra.dbg.DebuggerModelListener) -> None: ...

    @overload
    def addModelListener(self, __a0: ghidra.dbg.DebuggerModelListener, __a1: bool) -> None: ...

    def assertMine(self, __a0: java.lang.Class, __a1: ghidra.dbg.target.TargetObject) -> ghidra.dbg.target.TargetObject: ...

    def close(self) -> java.util.concurrent.CompletableFuture: ...

    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def fetchFreshChild(__a0: ghidra.dbg.target.TargetObject, __a1: unicode) -> java.util.concurrent.CompletableFuture: ...

    @overload
    def fetchModelObject(self, __a0: List[unicode]) -> java.util.concurrent.CompletableFuture: ...

    @overload
    def fetchModelObject(self, __a0: List[object]) -> java.util.concurrent.CompletableFuture: ...

    @overload
    def fetchModelObject(self, __a0: List[object], __a1: ghidra.dbg.DebuggerObjectModel.RefreshBehavior) -> java.util.concurrent.CompletableFuture: ...

    def fetchModelRoot(self) -> java.util.concurrent.CompletableFuture: ...

    @overload
    def fetchModelValue(self, __a0: List[unicode]) -> java.util.concurrent.CompletableFuture: ...

    @overload
    def fetchModelValue(self, __a0: List[object]) -> java.util.concurrent.CompletableFuture: ...

    @overload
    def fetchModelValue(self, __a0: List[object], __a1: ghidra.dbg.DebuggerObjectModel.RefreshBehavior) -> java.util.concurrent.CompletableFuture: ...

    def fetchObjectAttribute(self, __a0: List[object]) -> java.util.concurrent.CompletableFuture: ...

    @overload
    def fetchObjectAttributes(self, __a0: List[unicode]) -> java.util.concurrent.CompletableFuture: ...

    @overload
    def fetchObjectAttributes(self, __a0: List[object]) -> java.util.concurrent.CompletableFuture: ...

    @overload
    def fetchObjectAttributes(self, __a0: List[object], __a1: ghidra.dbg.DebuggerObjectModel.RefreshBehavior) -> java.util.concurrent.CompletableFuture: ...

    @overload
    def fetchObjectElements(self, __a0: List[unicode]) -> java.util.concurrent.CompletableFuture: ...

    @overload
    def fetchObjectElements(self, __a0: List[object]) -> java.util.concurrent.CompletableFuture: ...

    @overload
    def fetchObjectElements(self, __a0: List[object], __a1: ghidra.dbg.DebuggerObjectModel.RefreshBehavior) -> java.util.concurrent.CompletableFuture: ...

    @staticmethod
    def fetchSuccessorValue(__a0: ghidra.dbg.target.TargetObject, __a1: List[object], __a2: ghidra.dbg.DebuggerObjectModel.RefreshBehavior, __a3: bool) -> java.util.concurrent.CompletableFuture: ...

    @staticmethod
    def fetchSuccessorValueUsingAvailableCache(__a0: ghidra.dbg.target.TargetObject, __a1: List[object], __a2: bool) -> java.util.concurrent.CompletableFuture: ...

    def flushEvents(self) -> java.util.concurrent.CompletableFuture: ...

    def getAddress(self, __a0: unicode, __a1: long) -> ghidra.program.model.address.Address: ...

    def getAddressFactory(self) -> ghidra.program.model.address.AddressFactory: ...

    def getAddressSpace(self, __a0: unicode) -> ghidra.program.model.address.AddressSpace: ...

    def getBrief(self) -> unicode: ...

    def getClass(self) -> java.lang.Class: ...

    @overload
    def getModelObject(self, __a0: List[unicode]) -> ghidra.dbg.target.TargetObject: ...

    @overload
    def getModelObject(self, __a0: List[object]) -> ghidra.dbg.target.TargetObject: ...

    def getModelObjects(self, __a0: java.util.function.Predicate) -> java.util.Set: ...

    def getModelRoot(self) -> ghidra.dbg.target.TargetObject: ...

    def getModelValue(self, __a0: List[object]) -> object: ...

    def getObjectAttribute(self, __a0: List[unicode]) -> java.util.concurrent.CompletableFuture: ...

    def getRootSchema(self) -> ghidra.dbg.target.schema.TargetObjectSchema: ...

    def hashCode(self) -> int: ...

    def invalidateAllLocalCaches(self) -> None: ...

    def isAlive(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def ping(self, __a0: unicode) -> java.util.concurrent.CompletableFuture: ...

    def removeModelListener(self, __a0: ghidra.dbg.DebuggerModelListener) -> None: ...

    def reportError(self, __a0: object, __a1: unicode, __a2: java.lang.Throwable) -> None: ...

    @staticmethod
    def requireIface(__a0: java.lang.Class, __a1: ghidra.dbg.target.TargetObject, __a2: List[object]) -> ghidra.dbg.target.TargetObject: ...

    @staticmethod
    def requireIfaceName(__a0: java.lang.Class) -> unicode: ...

    @staticmethod
    def requireNonNull(__a0: object, __a1: List[object]) -> object: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def addressFactory(self) -> ghidra.program.model.address.AddressFactory: ...

    @property
    def alive(self) -> bool: ...

    @property
    def brief(self) -> unicode: ...

    @property
    def modelRoot(self) -> ghidra.dbg.target.TargetObject: ...

    @property
    def rootSchema(self) -> ghidra.dbg.target.schema.TargetObjectSchema: ...