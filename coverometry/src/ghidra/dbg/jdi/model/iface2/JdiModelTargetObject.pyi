from typing import List
import com.sun.jdi
import ghidra.dbg
import ghidra.dbg.agent
import ghidra.dbg.jdi.manager
import ghidra.dbg.jdi.model
import ghidra.dbg.jdi.model.iface2
import ghidra.dbg.target
import ghidra.dbg.target.schema
import ghidra.dbg.util
import java.lang
import java.util
import java.util.concurrent


class JdiModelTargetObject(ghidra.dbg.target.TargetObject, ghidra.dbg.agent.InvalidatableTargetObjectIf, object):
    ALL_INTERFACES: java.util.Set = [interface ghidra.dbg.target.TargetBreakpointLocationContainer, interface ghidra.dbg.target.TargetTogglable, interface ghidra.dbg.target.TargetBreakpointSpec, interface ghidra.dbg.target.TargetThread, interface ghidra.dbg.target.TargetSection, interface ghidra.dbg.target.TargetActiveScope, interface ghidra.dbg.target.TargetDataTypeMember, interface ghidra.dbg.target.TargetSymbol, interface ghidra.dbg.target.TargetInterruptible, interface ghidra.dbg.target.TargetStack, interface ghidra.dbg.target.TargetProcess, interface ghidra.dbg.target.TargetSectionContainer, interface ghidra.dbg.target.TargetKillable, interface ghidra.dbg.target.TargetAttacher, interface ghidra.dbg.target.TargetAccessConditioned, interface ghidra.dbg.target.TargetNamedDataType, interface ghidra.dbg.target.TargetInterpreter, interface ghidra.dbg.target.TargetFocusScope, interface ghidra.dbg.target.TargetAttachable, interface ghidra.dbg.target.TargetConsole, interface ghidra.dbg.target.TargetStackFrame, interface ghidra.dbg.target.TargetDeletable, interface ghidra.dbg.target.TargetSteppable, interface ghidra.dbg.target.TargetModuleContainer, interface ghidra.dbg.target.TargetExecutionStateful, interface ghidra.dbg.target.TargetBreakpointLocation, interface ghidra.dbg.target.TargetEnvironment, interface ghidra.dbg.target.TargetSymbolNamespace, interface ghidra.dbg.target.TargetRegister, interface ghidra.dbg.target.TargetBreakpointSpecContainer, interface ghidra.dbg.target.TargetResumable, interface ghidra.dbg.target.TargetEventScope, interface ghidra.dbg.target.TargetRegisterBank, interface ghidra.dbg.target.TargetDataTypeNamespace, interface ghidra.dbg.target.TargetRegisterContainer, interface ghidra.dbg.target.TargetMemoryRegion, interface ghidra.dbg.target.TargetLauncher, interface ghidra.dbg.target.TargetConfigurable, interface ghidra.dbg.target.TargetAggregate, interface ghidra.dbg.target.TargetDetachable, interface ghidra.dbg.target.TargetModule, interface ghidra.dbg.target.TargetMemory, interface ghidra.dbg.target.TargetMethod]
    DISPLAY_ATTRIBUTE_NAME: unicode = u'_display'
    INTERFACES_BY_NAME: java.util.Map = {u'SymbolNamespace': <type 'ghidra.dbg.target.TargetSymbolNamespace'>, u'BreakpointSpecContainer': <type 'ghidra.dbg.target.TargetBreakpointSpecContainer'>, u'Deletable': <type 'ghidra.dbg.target.TargetDeletable'>, u'Register': <type 'ghidra.dbg.target.TargetRegister'>, u'Thread': <type 'ghidra.dbg.target.TargetThread'>, u'SectionContainer': <type 'ghidra.dbg.target.TargetSectionContainer'>, u'Symbol': <type 'ghidra.dbg.target.TargetSymbol'>, u'Launcher': <type 'ghidra.dbg.target.TargetLauncher'>, u'Resumable': <type 'ghidra.dbg.target.TargetResumable'>, u'Method': <type 'ghidra.dbg.target.TargetMethod'>, u'ExecutionStateful': <type 'ghidra.dbg.target.TargetExecutionStateful'>, u'MemoryRegion': <type 'ghidra.dbg.target.TargetMemoryRegion'>, u'TypeMember': <type 'ghidra.dbg.target.TargetDataTypeMember'>, u'BreakpointSpec': <type 'ghidra.dbg.target.TargetBreakpointSpec'>, u'Aggregate': <type 'ghidra.dbg.target.TargetAggregate'>, u'Module': <type 'ghidra.dbg.target.TargetModule'>, u'Detachable': <type 'ghidra.dbg.target.TargetDetachable'>, u'Access': <type 'ghidra.dbg.target.TargetAccessConditioned'>, u'Attachable': <type 'ghidra.dbg.target.TargetAttachable'>, u'Environment': <type 'ghidra.dbg.target.TargetEnvironment'>, u'ModuleContainer': <type 'ghidra.dbg.target.TargetModuleContainer'>, u'Interpreter': <type 'ghidra.dbg.target.TargetInterpreter'>, u'Steppable': <type 'ghidra.dbg.target.TargetSteppable'>, u'Process': <type 'ghidra.dbg.target.TargetProcess'>, u'Attacher': <type 'ghidra.dbg.target.TargetAttacher'>, u'RegisterBank': <type 'ghidra.dbg.target.TargetRegisterBank'>, u'Section': <type 'ghidra.dbg.target.TargetSection'>, u'DataType': <type 'ghidra.dbg.target.TargetNamedDataType'>, u'Memory': <type 'ghidra.dbg.target.TargetMemory'>, u'Killable': <type 'ghidra.dbg.target.TargetKillable'>, u'Interruptible': <type 'ghidra.dbg.target.TargetInterruptible'>, u'StackFrame': <type 'ghidra.dbg.target.TargetStackFrame'>, u'Togglable': <type 'ghidra.dbg.target.TargetTogglable'>, u'ActiveScope': <type 'ghidra.dbg.target.TargetActiveScope'>, u'Console': <type 'ghidra.dbg.target.TargetConsole'>, u'EventScope': <type 'ghidra.dbg.target.TargetEventScope'>, u'Stack': <type 'ghidra.dbg.target.TargetStack'>, u'BreakpointLocation': <type 'ghidra.dbg.target.TargetBreakpointLocation'>, u'FocusScope': <type 'ghidra.dbg.target.TargetFocusScope'>, u'RegisterContainer': <type 'ghidra.dbg.target.TargetRegisterContainer'>, u'BreakpointLocationContainer': <type 'ghidra.dbg.target.TargetBreakpointLocationContainer'>, u'Configurable': <type 'ghidra.dbg.target.TargetConfigurable'>, u'DataTypeNamespace': <type 'ghidra.dbg.target.TargetDataTypeNamespace'>}
    KIND_ATTRIBUTE_NAME: unicode = u'_kind'
    LOCATION_ATTRIBUTE_NAME: unicode = u'Location'
    MODIFIED_ATTRIBUTE_NAME: unicode = u'_modified'
    ORDER_ATTRIBUTE_NAME: unicode = u'_order'
    PREFIX_INVISIBLE: unicode = u'_'
    SHORT_DISPLAY_ATTRIBUTE_NAME: unicode = u'_short_display'
    THIS_OBJECT_ATTRIBUTE_NAME: unicode = u'This'
    THREAD_ATTRIBUTE_NAME: unicode = u'Thread'
    TYPE_ATTRIBUTE_NAME: unicode = u'_type'
    VALUE_ATTRIBUTE_NAME: unicode = u'_value'







    def acceptsElement(self, __a0: unicode) -> bool: ...

    def as(self, __a0: java.lang.Class) -> ghidra.dbg.target.TargetObject: ...

    def changeAttributes(self, __a0: List[object], __a1: java.util.Map, __a2: unicode) -> ghidra.dbg.util.CollectionUtils.Delta: ...

    @overload
    def compareTo(self, __a0: ghidra.dbg.target.TargetObject) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def computeHashCode(self) -> int: ...

    def doEquals(self, __a0: object) -> bool: ...

    def doInvalidateSubtree(self, __a0: ghidra.dbg.target.TargetObject, __a1: unicode) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def fetchAttribute(self, __a0: unicode) -> java.util.concurrent.CompletableFuture: ...

    @overload
    def fetchAttributes(self) -> java.util.concurrent.CompletableFuture: ...

    @overload
    def fetchAttributes(self, __a0: ghidra.dbg.DebuggerObjectModel.RefreshBehavior) -> java.util.concurrent.CompletableFuture: ...

    def fetchChild(self, __a0: unicode) -> java.util.concurrent.CompletableFuture: ...

    @overload
    def fetchChildren(self) -> java.util.concurrent.CompletableFuture: ...

    @overload
    def fetchChildren(self, __a0: ghidra.dbg.DebuggerObjectModel.RefreshBehavior) -> java.util.concurrent.CompletableFuture: ...

    def fetchChildrenSupporting(self, __a0: java.lang.Class) -> java.util.concurrent.CompletableFuture: ...

    def fetchElement(self, __a0: unicode) -> java.util.concurrent.CompletableFuture: ...

    @overload
    def fetchElements(self) -> java.util.concurrent.CompletableFuture: ...

    @overload
    def fetchElements(self, __a0: ghidra.dbg.DebuggerObjectModel.RefreshBehavior) -> java.util.concurrent.CompletableFuture: ...

    @overload
    def fetchSubAttribute(self, __a0: List[unicode]) -> java.util.concurrent.CompletableFuture: ...

    @overload
    def fetchSubAttribute(self, __a0: List[object]) -> java.util.concurrent.CompletableFuture: ...

    @overload
    def fetchSubAttributes(self, __a0: List[unicode]) -> java.util.concurrent.CompletableFuture: ...

    @overload
    def fetchSubAttributes(self, __a0: List[object]) -> java.util.concurrent.CompletableFuture: ...

    @overload
    def fetchSubElements(self, __a0: List[unicode]) -> java.util.concurrent.CompletableFuture: ...

    @overload
    def fetchSubElements(self, __a0: List[object]) -> java.util.concurrent.CompletableFuture: ...

    @overload
    def fetchSuccessor(self, __a0: List[unicode]) -> java.util.concurrent.CompletableFuture: ...

    @overload
    def fetchSuccessor(self, __a0: List[object]) -> java.util.concurrent.CompletableFuture: ...

    @overload
    def fetchValue(self, __a0: List[unicode]) -> java.util.concurrent.CompletableFuture: ...

    @overload
    def fetchValue(self, __a0: List[object]) -> java.util.concurrent.CompletableFuture: ...

    def getCachedAttribute(self, __a0: unicode) -> object: ...

    def getCachedAttributes(self) -> java.util.Map: ...

    def getCachedElements(self) -> java.util.Map: ...

    def getCachedSuitable(self, __a0: java.lang.Class) -> ghidra.dbg.target.TargetObject: ...

    def getCallbackAttributes(self) -> java.util.Map: ...

    def getCallbackElements(self) -> java.util.Map: ...

    def getClass(self) -> java.lang.Class: ...

    def getDisplay(self) -> unicode: ...

    def getIndex(self) -> unicode: ...

    def getInstance(self, __a0: com.sun.jdi.Mirror) -> ghidra.dbg.jdi.model.iface2.JdiModelTargetObject: ...

    def getInterfaceNames(self) -> java.util.Collection: ...

    def getInterfaces(self) -> java.util.Collection: ...

    @staticmethod
    def getInterfacesByName(__a0: java.util.Collection) -> List[object]: ...

    def getJoinedPath(self, __a0: unicode) -> unicode: ...

    def getKind(self) -> unicode: ...

    def getManager(self) -> ghidra.dbg.jdi.manager.JdiManager: ...

    def getModel(self) -> ghidra.dbg.DebuggerObjectModel: ...

    def getModelImpl(self) -> ghidra.dbg.jdi.model.JdiModelImpl: ...

    def getName(self) -> unicode: ...

    def getObject(self) -> object: ...

    def getOrder(self) -> int: ...

    def getParent(self) -> ghidra.dbg.target.TargetObject: ...

    def getPath(self) -> List[object]: ...

    def getProtocolID(self) -> object: ...

    def getSchema(self) -> ghidra.dbg.target.schema.TargetObjectSchema: ...

    def getShortDisplay(self) -> unicode: ...

    @overload
    def getSuccessor(self, __a0: List[unicode]) -> ghidra.dbg.target.TargetObject: ...

    @overload
    def getSuccessor(self, __a0: List[object]) -> ghidra.dbg.target.TargetObject: ...

    def getTargetObject(self, __a0: object) -> ghidra.dbg.jdi.model.iface2.JdiModelTargetObject: ...

    def getType(self) -> unicode: ...

    def getTypeHint(self) -> unicode: ...

    def getTypedAttributeNowByName(self, __a0: unicode, __a1: java.lang.Class, __a2: object) -> object: ...

    def getValue(self) -> object: ...

    def hashCode(self) -> int: ...

    def init(self, __a0: java.util.Map) -> java.util.concurrent.CompletableFuture: ...

    @staticmethod
    def initInterfacesByName() -> java.util.Map: ...

    def invalidateCaches(self) -> java.util.concurrent.CompletableFuture: ...

    def invalidateSubtree(self, __a0: ghidra.dbg.target.TargetObject, __a1: unicode) -> None: ...

    def isModified(self) -> bool: ...

    def isRoot(self) -> bool: ...

    def isValid(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @overload
    def resync(self) -> java.util.concurrent.CompletableFuture: ...

    @overload
    def resync(self, __a0: ghidra.dbg.DebuggerObjectModel.RefreshBehavior, __a1: ghidra.dbg.DebuggerObjectModel.RefreshBehavior) -> java.util.concurrent.CompletableFuture: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def cachedAttributes(self) -> java.util.Map: ...

    @property
    def cachedElements(self) -> java.util.Map: ...

    @property
    def callbackAttributes(self) -> java.util.Map: ...

    @property
    def callbackElements(self) -> java.util.Map: ...

    @property
    def display(self) -> unicode: ...

    @property
    def index(self) -> unicode: ...

    @property
    def interfaceNames(self) -> java.util.Collection: ...

    @property
    def interfaces(self) -> java.util.Collection: ...

    @property
    def kind(self) -> unicode: ...

    @property
    def manager(self) -> ghidra.dbg.jdi.manager.JdiManager: ...

    @property
    def model(self) -> ghidra.dbg.DebuggerObjectModel: ...

    @property
    def modelImpl(self) -> ghidra.dbg.jdi.model.JdiModelImpl: ...

    @property
    def name(self) -> unicode: ...

    @property
    def object(self) -> object: ...

    @property
    def order(self) -> int: ...

    @property
    def parent(self) -> ghidra.dbg.target.TargetObject: ...

    @property
    def path(self) -> List[object]: ...

    @property
    def protocolID(self) -> object: ...

    @property
    def root(self) -> bool: ...

    @property
    def schema(self) -> ghidra.dbg.target.schema.TargetObjectSchema: ...

    @property
    def shortDisplay(self) -> unicode: ...

    @property
    def type(self) -> unicode: ...

    @property
    def typeHint(self) -> unicode: ...

    @property
    def valid(self) -> bool: ...

    @property
    def value(self) -> object: ...