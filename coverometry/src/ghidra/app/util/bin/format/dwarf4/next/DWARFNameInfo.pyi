from typing import List
import ghidra.app.util.bin.format.dwarf4.next
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.program.model.symbol
import java.lang


class DWARFNameInfo(object):
    """
    A immutable hierarchical path based name implementation that can be viewed as either
     Namespace or CategoryPath.
 
    """









    def asCategoryPath(self) -> ghidra.program.model.data.CategoryPath:
        """
        Converts this object into an equiv {@link CategoryPath}.
        @return {@link CategoryPath}: "/organizational_cat_path/namespace1/namespace2/obj_name"
        """
        ...

    def asDataTypePath(self) -> ghidra.program.model.data.DataTypePath:
        """
        Converts this object into an equiv {@link DataTypePath}.
        @return {@link DataTypePath}: { "/organizational_cat_path/namespace1/namespace2", "obj_name" }
        """
        ...

    def asNamespace(self, program: ghidra.program.model.listing.Program) -> ghidra.program.model.symbol.Namespace:
        """
        Converts this object into an equiv Ghidra {@link Namespace}, omitting the organizational
         category path (which only applies to DataTypes).
        @param program {@link Program} where the namespace lives.
        @return {@link Namespace}: "ROOT::namespace1::namespace2::obj_name"
        """
        ...

    def createChild(self, childOriginalName: unicode, childName: unicode, childType: ghidra.program.model.symbol.SymbolType) -> ghidra.app.util.bin.format.dwarf4.next.DWARFNameInfo:
        """
        Creates a {@link DWARFNameInfo} instance, which has a name that is contained with
         this instance's namespace, using the specified name and symbol type.
        @param childOriginalName the unmodified name
        @param childName the ghidra-ized name of the type/symbol/namespace/etc
        @param childType the type of the object being named
        @return new DWARFNameInfo instance
        """
        ...

    @staticmethod
    def createRoot(rootCategory: ghidra.program.model.data.CategoryPath) -> ghidra.app.util.bin.format.dwarf4.next.DWARFNameInfo:
        """
        Create a root name entry that will serve as the parent for all children.
        @param rootCategory {@link CategoryPath} in the data type manager that will contain
         any sub-categories that represent namespaces
        @return a new {@link DWARFNameInfo} instance
        """
        ...

    def equals(self, obj: object) -> bool: ...

    @staticmethod
    def fromDataType(dataType: ghidra.program.model.data.DataType) -> ghidra.app.util.bin.format.dwarf4.next.DWARFNameInfo:
        """
        Create a {@link DWARFNameInfo} instance using the specified {@link DataType}'s name.
        @param dataType {@link DataType}
        @return new {@link DWARFNameInfo} using the same name / CategoryPath as the data type
        """
        ...

    @staticmethod
    def fromList(__a0: ghidra.app.util.bin.format.dwarf4.next.DWARFNameInfo, __a1: List[object]) -> ghidra.app.util.bin.format.dwarf4.next.DWARFNameInfo: ...

    def getClass(self) -> java.lang.Class: ...

    def getName(self) -> unicode:
        """
        Returns the name of this entry.
        @return string name of this entry, safe to use to name a Ghidra object (datatype, namespace,
         etc)
        """
        ...

    def getNamespacePath(self) -> ghidra.app.util.bin.format.dwarf4.next.NamespacePath:
        """
        Returns the NamespacePath of this instance.
        @return {@link NamespacePath} of this instance
        """
        ...

    def getOrganizationalCategoryPath(self) -> ghidra.program.model.data.CategoryPath:
        """
        Returns the organizational category path.
        @return organizational category path for dwarf names
        """
        ...

    def getOriginalName(self) -> unicode:
        """
        Returns the original name (unmodified by Ghidra-isms) of this entry.
        @return original name
        """
        ...

    def getParent(self) -> ghidra.app.util.bin.format.dwarf4.next.DWARFNameInfo:
        """
        Returns the parent name
        @return parent
        """
        ...

    def getParentCP(self) -> ghidra.program.model.data.CategoryPath:
        """
        Returns the parent's CategoryPath.
        @return parent name's CategoryPath
        """
        ...

    def getParentNamespace(self, program: ghidra.program.model.listing.Program) -> ghidra.program.model.symbol.Namespace:
        """
        Returns the Ghidra {@link Namespace} that represents this entry's parent.
        @param program the Ghidra program that contains the namespace
        @return {@link Namespace} representing this entry's parent
        """
        ...

    def getType(self) -> ghidra.program.model.symbol.SymbolType:
        """
        Returns the SymbolType of this name.
        @return {@link SymbolType} of this entry
        """
        ...

    def hashCode(self) -> int: ...

    def isAnon(self) -> bool:
        """
        Returns true if the original name of this entry was blank.
        @return boolean true if there was no original name
        """
        ...

    def isNameModified(self) -> bool:
        """
        Returns true if this instance's {@link #getName() name} value is different
         than its {@link #getOriginalName() original} form.
         <p>
        @return boolean true if the original name doesn't match the ghidra-ized name
        """
        ...

    def isRoot(self) -> bool:
        """
        Returns true if this instance has no parent and is considered the root.
        @return boolean true if root name, false if not root
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def replaceName(self, newName: unicode, newOriginalName: unicode) -> ghidra.app.util.bin.format.dwarf4.next.DWARFNameInfo:
        """
        Creates a new DWARFNameInfo instance, using this instance as the template, replacing
         the name with a new name.
        @param newName name for the new instance
        @param newOriginalName originalName for the new instance
        @return new instance with new name
        """
        ...

    def replaceType(self, newType: ghidra.program.model.symbol.SymbolType) -> ghidra.app.util.bin.format.dwarf4.next.DWARFNameInfo:
        """
        Creates a new DWARFNameInfo instance, using this instance as the template, replacing
         the SymbolType with a new value.
        @param newType new SymbolType value
        @return new instance with the specified SymbolType
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
    def anon(self) -> bool: ...

    @property
    def name(self) -> unicode: ...

    @property
    def nameModified(self) -> bool: ...

    @property
    def namespacePath(self) -> ghidra.app.util.bin.format.dwarf4.next.NamespacePath: ...

    @property
    def organizationalCategoryPath(self) -> ghidra.program.model.data.CategoryPath: ...

    @property
    def originalName(self) -> unicode: ...

    @property
    def parent(self) -> ghidra.app.util.bin.format.dwarf4.next.DWARFNameInfo: ...

    @property
    def parentCP(self) -> ghidra.program.model.data.CategoryPath: ...

    @property
    def root(self) -> bool: ...

    @property
    def type(self) -> ghidra.program.model.symbol.SymbolType: ...