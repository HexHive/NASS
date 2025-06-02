from typing import Iterator
from typing import List
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.symbol
import java.lang


class SymbolTable(object):
    """
    A SymbolTable manages the Symbols defined in a program.
 
     A Symbol is an association between an Address, a String name. In addition, symbols may have one
     or more References.
 
     A Reference is a 4-tuple of a source address, destination address, type, and either a mnemonic or
     operand index.
 
     Any address in a program can have more than one symbol associated to it. At any given time, one
     and only one symbol will be designated as the primary.
 
     A symbol can be either global or local. Local symbols belong to some namespace other than the
     global namespace.
 
     Label and Function symbols do not have to have unique names with a namespace. All other symbols
     must be unique within a namespace and be unique with all other symbols that must be unique. In
     other words, you can have several functions named "foo" and several labels named "foo" in the
     same namespace. But you can't have a class named "foo" and a namespace named "foo". But you can
     have a class named "foo" and many functions and labels named "foo" all in the same namespace.
 
     A symbol can also be designated as dynamic. Which means the name is generated on-the-fly by the
     system based on its context.
    """









    def addExternalEntryPoint(self, addr: ghidra.program.model.address.Address) -> None:
        """
        Add a memory address to the external entry points.
        @param addr the memory address to add
        @throws IllegalArgumentException if a non-memory is specified
        """
        ...

    def convertNamespaceToClass(self, namespace: ghidra.program.model.symbol.Namespace) -> ghidra.program.model.listing.GhidraClass:
        """
        Convert the given namespace to a class namespace
        @param namespace the namespace to convert
        @return the new class
        @throws ConcurrentModificationException if the given parent namespace has been deleted
        @throws IllegalArgumentException if the given parent namespace is from a different program
                     than that of this symbol table or the namespace not allowed (e.g., global or
                     library namespace).
        """
        ...

    def createClass(self, parent: ghidra.program.model.symbol.Namespace, name: unicode, source: ghidra.program.model.symbol.SourceType) -> ghidra.program.model.listing.GhidraClass:
        """
        Create a class namespace in the given parent namespace
        @param parent the parent namespace, or null for the global namespace
        @param name the name of the namespace
        @param source the source of this class namespace's symbol
        @return the new class namespace
        @throws DuplicateNameException thrown if another non function or label symbol exists with the
                     given name
        @throws InvalidInputException throw if the name has invalid characters or is null
        @throws IllegalArgumentException if the given parent namespace is from a different program
                     than that of this symbol table or if source is {@link SourceType#DEFAULT}
        """
        ...

    def createExternalLibrary(self, name: unicode, source: ghidra.program.model.symbol.SourceType) -> ghidra.program.model.listing.Library:
        """
        Create a library namespace with the given name
        @param name the name of the new library namespace
        @param source the source of this external library's symbol
        @return the new library namespace
        @throws InvalidInputException if the name is invalid
        @throws IllegalArgumentException if you try to set the source to {@link SourceType#DEFAULT}
        @throws DuplicateNameException thrown if another non function or label symbol exists with the
                     given name
        """
        ...

    @overload
    def createLabel(self, addr: ghidra.program.model.address.Address, name: unicode, source: ghidra.program.model.symbol.SourceType) -> ghidra.program.model.symbol.Symbol:
        """
        Create a label symbol with the given name in the global namespace and associated to the 
         given memory address. (see {@link Address#isMemoryAddress()}).
         <p>
         The new symbol will be of type {@link SymbolType#LABEL} or {@link SymbolType#FUNCTION} if a 
         default function symbol currently exists at the address. If a default function symbol exists 
         at the specified address the function symbol will be renamed and returned.  Label and function
         symbols do not need to be unique across multiple addresses.  However, if a global symbol at 
         the specified address already has the specified name it will be returned without changing the 
         source type.  If this is the first non-dynamic symbol defined for the address it becomes the 
         primary symbol.
        @param addr the memory address at which to create a symbol
        @param name the name of the symbol
        @param source the source of this symbol.  In general, a source of {@link SourceType#DEFAULT} 
                     should never be specified using this method.
        @return new labe or function symbol
        @throws InvalidInputException if name contains white space, is zero length, or is null for
                     non-default source
        @throws IllegalArgumentException if {@link SourceType#DEFAULT} is improperly specified, or 
                     a non-memory address.
        """
        ...

    @overload
    def createLabel(self, addr: ghidra.program.model.address.Address, name: unicode, namespace: ghidra.program.model.symbol.Namespace, source: ghidra.program.model.symbol.SourceType) -> ghidra.program.model.symbol.Symbol:
        """
        Create a label symbol with the given name and namespace associated to the given memory 
         address.  (see {@link Address#isMemoryAddress()}).
         <p>
         The new symbol will be of type {@link SymbolType#LABEL} or {@link SymbolType#FUNCTION} if a 
         default function symbol currently exists at the address. If a default function symbol exists 
         at the specified address the function symbol will be renamed and returned.  Label and function
         symbols do not need to be unique across multiple addresses or namespaces.  However, if a 
         symbol at the specified address already has the specified name and namespace it will be 
         returned without changing the source type.  If this is the first non-dynamic symbol defined 
         for the address it becomes the primary symbol.
        @param addr the address at which to create a symbol
        @param name the name of the symbol
        @param namespace the parent namespace of the symbol, or null for the global namespace.
        @param source the source of this symbol. In general, a source of {@link SourceType#DEFAULT} 
                     should never be specified using this method.
        @return new label or function symbol
        @throws InvalidInputException if name contains white space, is zero length, or is null for
                     non-default source. Also thrown if invalid parent namespace is specified.
        @throws IllegalArgumentException if {@link SourceType#DEFAULT} is improperly specified, or 
                     a non-memory address, or if the given parent namespace is from a different 
                     program than that of this symbol table.
        """
        ...

    def createNameSpace(self, parent: ghidra.program.model.symbol.Namespace, name: unicode, source: ghidra.program.model.symbol.SourceType) -> ghidra.program.model.symbol.Namespace:
        """
        Create a new namespace
        @param parent the parent of the new namespace, or null for the global namespace
        @param name the name of the new namespace
        @param source the source of this namespace's symbol
        @return the new namespace
        @throws DuplicateNameException if another non function or label symbol exists with the given
                     name
        @throws InvalidInputException if the name is invalid
        @throws IllegalArgumentException if the given parent namespace is from a different program
                     than that of this symbol table or if source is {@link SourceType#DEFAULT}
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getAllSymbols(self, includeDynamicSymbols: bool) -> ghidra.program.model.symbol.SymbolIterator:
        """
        Get all of the symbols, optionally including dynamic symbols
        @param includeDynamicSymbols if true, the iterator will include dynamic symbols
        @return an iterator over the symbols
        """
        ...

    def getChildren(self, parentSymbol: ghidra.program.model.symbol.Symbol) -> ghidra.program.model.symbol.SymbolIterator:
        """
        Get all symbols that have the given parent symbol
         <p>
         <b>NOTE:</b> The resulting iterator will not return default thunks (i.e., thunk function
         symbol with default source type) or global dynamic label symbols.
        @param parentSymbol the parent symbol
        @return symbol iterator
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getClassNamespaces(self) -> Iterator[ghidra.program.model.listing.GhidraClass]:
        """
        Get all class namespaces defined within the program, in no particular order
        @return an iterator over the classes
        """
        ...

    def getClassSymbol(self, name: unicode, namespace: ghidra.program.model.symbol.Namespace) -> ghidra.program.model.symbol.Symbol:
        """
        Get the class symbol with the given name in the given namespace
        @param name the name of the class
        @param namespace the parent namespace to search for the class
        @return the class symbol with the given name in the given namespace
        @throws IllegalArgumentException if the given parent namespace is from a different program
                 than that of this symbol table
        """
        ...

    def getDefinedSymbols(self) -> ghidra.program.model.symbol.SymbolIterator:
        """
        Get all defined symbols in no particular order.  All global dynamic memory labels will be 
         excluded.
        @return symbol iterator
        """
        ...

    def getDynamicSymbolID(self, addr: ghidra.program.model.address.Address) -> long:
        """
        Get the unique symbol ID for a dynamic symbol at the specified address
         <p>
         Having a dynamic symbol ID does not imply that a dynamic symbol actually exists. Rather, this
         just gives the ID that a dynamic symbol at that address would have, should it ever exist.
         <p>
         <b>NOTE:</b> This symbol ID should not be permanently stored since the encoding may change
         between software releases.
        @param addr the dynamic symbol memory address
        @return unique symbol ID
        @throws IllegalArgumentException if a non-memory address is specified
        """
        ...

    def getExternalEntryPointIterator(self) -> ghidra.program.model.address.AddressIterator:
        """
        Get the external entry points (addresses)
        @return entry-point address iterator
        """
        ...

    def getExternalSymbol(self, name: unicode) -> ghidra.program.model.symbol.Symbol:
        """
        Get the external symbol with the given name.  The first occurrence of the named symbol found
         within any external namespace will be returned.  If all matching symbols need to be
         considered the {@link #getExternalSymbols(String)} should be used.
        @param name the name of the symbol
        @return the symbol, or null if no external symbol has that name
        """
        ...

    @overload
    def getExternalSymbols(self) -> ghidra.program.model.symbol.SymbolIterator:
        """
        Get all defined external symbols in no particular order
        @return symbol iterator
        """
        ...

    @overload
    def getExternalSymbols(self, name: unicode) -> ghidra.program.model.symbol.SymbolIterator:
        """
        Get all the external symbols with the given name
        @param name the name of symbols
        @return an iterator over the symbols
        """
        ...

    def getGlobalSymbol(self, name: unicode, addr: ghidra.program.model.address.Address) -> ghidra.program.model.symbol.Symbol:
        """
        Get the global symbol with the given name and address.
         <p>
         Note that this results in a single Symbol because of an additional restriction that allows
         only one symbol with a given name at the same address and namespace (in this case the global
         namespace).
         <p>
         This is just a convenience method for {@link #getSymbol(String, Address, Namespace)} where
         the namespace is the global namespace.
         <p>
         <b>NOTE:</b> This method will not return a default thunk (i.e., thunk function symbol with
         default source type) since it mirrors the name and parent namespace of the function it
         thunks.
        @param name the name of the symbol to retrieve
        @param addr the address of the symbol to retrieve
        @return the symbol which matches the specified criteria in the global namespace or null if
                 not found
        @see #getSymbol(String, Address, Namespace)
        """
        ...

    def getGlobalSymbols(self, name: unicode) -> List[ghidra.program.model.symbol.Symbol]:
        """
        Get a list of all global symbols with the given name.  Matches against dynamic label symbols 
         will be included.  
         <p>
         <b>NOTE:</b> This method will not return default thunks (i.e., thunk function symbol with
         default source type).
        @param name the name of the symbols to retrieve
        @return a list of all global symbols with the given name
        """
        ...

    @overload
    def getLabelHistory(self) -> Iterator[ghidra.program.model.symbol.LabelHistory]:
        """
        Get the complete label history of the program
        @return an iterator over history entries
        """
        ...

    @overload
    def getLabelHistory(self, addr: ghidra.program.model.address.Address) -> List[ghidra.program.model.symbol.LabelHistory]:
        """
        Get the label history for the given address
         <p>
         Each entry records a change made to the labels at the given address
        @param addr address of the label change
        @return array of history objects
        """
        ...

    def getLabelOrFunctionSymbols(self, name: unicode, namespace: ghidra.program.model.symbol.Namespace) -> List[ghidra.program.model.symbol.Symbol]:
        """
        Get all the label or function symbols that have the given name in the given parent namespace.
         If the global namespace is specified matches against dynamic label symbols will be included.  
         <p>
         <b>NOTE:</b> If a function namespace is specified default parameter and local variable names 
         will be included.  If an external library or namespace is specified default external 
         label/function symbols will be included.
         <p>
         <b>NOTE:</b> This method will not return a default thunk (i.e., thunk function symbol with
         default source type) since it mirrors the name and parent namespace of the function it
         thunks.
        @param name the name of the symbols to search for
        @param namespace the namespace to search. If null, then the global namespace is assumed.
        @return a list of all the label or function symbols with the given name in the given parent
                 namespace
        @throws IllegalArgumentException if the given parent namespace is from a different program
                 than that of this symbol table
        """
        ...

    def getLibrarySymbol(self, name: unicode) -> ghidra.program.model.symbol.Symbol:
        """
        Get the library symbol with the given name
        @param name the name of the library symbol to retrieve
        @return the library symbol with the given name
        """
        ...

    def getLocalVariableSymbol(self, name: unicode, namespace: ghidra.program.model.symbol.Namespace) -> ghidra.program.model.symbol.Symbol:
        """
        Get the local variable symbol with the given name in the given namespace
        @param name the name of the local variable
        @param namespace the parent namespace (function) to search for the local variable
        @return the local variable symbol with the given name in the given namespace
        @throws IllegalArgumentException if the given parent namespace is from a different program
                 than that of this symbol table
        """
        ...

    @overload
    def getNamespace(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.symbol.Namespace:
        """
        Get the deepest namespace containing the given address
        @param addr the address contained in the namespace
        @return the deepest namespace which contains the address
        """
        ...

    @overload
    def getNamespace(self, name: unicode, namespace: ghidra.program.model.symbol.Namespace) -> ghidra.program.model.symbol.Namespace:
        """
        Get the namespace with the given name in the given parent namespace.
         <p>
         The returned namespace can be a generic namespace ({@link SymbolType#NAMESPACE}, 
         {@link NamespaceSymbol}), class ({@link SymbolType#CLASS}, {@link ClassSymbol}),or 
         library ({@link SymbolType#LIBRARY}, {@link LibrarySymbol}), but not a function.
         <p>
         There can be only one because these symbol types have a unique name 
         requirement within their parent namespace.
        @param name the name of the namespace to be retrieved
        @param namespace the parent namespace of the namespace to be retrieved
        @return the namespace with the given name in the given parent namespace
        @throws IllegalArgumentException if the given parent namespace is from a different program
                 than that of this symbol table
        """
        ...

    def getNamespaceSymbol(self, name: unicode, namespace: ghidra.program.model.symbol.Namespace) -> ghidra.program.model.symbol.Symbol:
        """
        Get a generic namespace symbol with the given name in the given parent namespace
        @param name the name of the namespace symbol to retrieve
        @param namespace the namespace containing the symbol to retrieve
        @return the symbol, or null
        @throws IllegalArgumentException if the given parent namespace is from a different program
                 than that of this symbol table
        """
        ...

    def getNumSymbols(self) -> int:
        """
        Get the total number of symbols in the table
        @return total number of symbols
        """
        ...

    def getOrCreateNameSpace(self, parent: ghidra.program.model.symbol.Namespace, name: unicode, source: ghidra.program.model.symbol.SourceType) -> ghidra.program.model.symbol.Namespace:
        """
        Get or create the namespace with the given name in the given parent
         <p>
         If the namespace does not already exists, then it will be created.
        @param parent the parent namespace
        @param name the namespace name
        @param source the source type for the namespace if it is created
        @return the namespace
        @throws DuplicateNameException if another non function or label symbol exists with the given
                     name
        @throws InvalidInputException if the name is invalid
        @throws IllegalArgumentException if the given parent namespace is from a different program
                     than that of this symbol table
        @throws ConcurrentModificationException if the given parent namespace has been deleted
        """
        ...

    def getParameterSymbol(self, name: unicode, namespace: ghidra.program.model.symbol.Namespace) -> ghidra.program.model.symbol.Symbol:
        """
        Get the parameter symbol with the given name in the given namespace
        @param name the name of the parameter
        @param namespace the namespace (function) to search for the class
        @return the parameter symbol with the given name in the given namespace
        @throws IllegalArgumentException if the given parent namespace is from a different program
                 than that of this symbol table
        """
        ...

    def getPrimarySymbol(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.symbol.Symbol:
        """
        Get the primary label or function symbol at the given address
         <p>
         This method will return null if the address specified is neither a memory address nor an
         external address.
        @param addr the address of the symbol
        @return the symbol, or null if no symbol is at the address
        """
        ...

    @overload
    def getPrimarySymbolIterator(self, forward: bool) -> ghidra.program.model.symbol.SymbolIterator:
        """
        Get all primary label and function symbols defined within program memory address.
         Iteration may span multiple memory spaces. 
         <p>
         <b>NOTE:</b> The returned symbols will not include any external symbols defined within the 
         {@link AddressSpace#EXTERNAL_SPACE}.  In addition, all global dynamic label symbols will 
         be omitted.
        @param forward true means the iterator is in the forward direction
        @return symbol iterator
        """
        ...

    @overload
    def getPrimarySymbolIterator(self, startAddr: ghidra.program.model.address.Address, forward: bool) -> ghidra.program.model.symbol.SymbolIterator:
        """
        Get all primary label and function symbols starting at the specified memory address through 
         to the program's maximum memory address.  Iteration may span multiple memory spaces. 
         <p>
         <b>NOTE:</b> The returned symbols will not include any external symbols defined within the 
         {@link AddressSpace#EXTERNAL_SPACE}.  In addition, all global dynamic label symbols will 
         be omitted.
        @param startAddr the starting memory address
        @param forward true means the iterator is in the forward direction
        @return symbol iterator
        @throws IllegalArgumentException if a non-memory address is specified
        """
        ...

    @overload
    def getPrimarySymbolIterator(self, addressSet: ghidra.program.model.address.AddressSetView, forward: bool) -> ghidra.program.model.symbol.SymbolIterator:
        """
        Get primary label and function symbols within the given address set.  
         <p>
         <b>NOTE:</b> All external symbols will be omitted unless the full 
         {@link AddressSpace#EXTERNAL_SPACE} range is included within the specified address set
         or a null addressSet is specified.  All global dynamic label symbols will be omitted.
        @param addressSet the set of address containing the symbols.  A null value may be specified
         to include all memory and external primary symbols.
        @param forward true means the iterator is in the forward direction
        @return symbol iterator
        """
        ...

    @overload
    def getSymbol(self, symbolID: long) -> ghidra.program.model.symbol.Symbol:
        """
        Get the symbol for the given symbol ID.
        @param symbolID the id of the symbol to be retrieved
        @return null if there is no symbol with the given ID
        """
        ...

    @overload
    def getSymbol(self, ref: ghidra.program.model.symbol.Reference) -> ghidra.program.model.symbol.Symbol:
        """
        Get the symbol that a given reference associates
        @param ref the reference for the associated symbol
        @return the associated symbol
        """
        ...

    @overload
    def getSymbol(self, name: unicode, addr: ghidra.program.model.address.Address, namespace: ghidra.program.model.symbol.Namespace) -> ghidra.program.model.symbol.Symbol:
        """
        Get the symbol with the given name, address, and namespace.
         <p>
         Note that for a symbol to be uniquely specified, all these parameters are required. Any
         method that queries for symbols using just one or two of these parameters will return only
         the first match.
         <p>
         <b>NOTE:</b> This method will not return a default thunk (i.e., thunk function symbol with
         default source type) since it mirrors the name and parent namespace of the function it
         thunks.
        @param name the name of the symbol to retrieve
        @param addr the address of the symbol to retrieve
        @param namespace the namespace of the symbol to retrieve. May be null which indicates the
                    global namespace.
        @return the symbol which matches the specified criteria or null if not found
        @throws IllegalArgumentException if the given parent namespace is from a different program
                     than that of this symbol table
        @see #getGlobalSymbol(String, Address) for a convenience method if the namespace is the
              global namespace.
        """
        ...

    @overload
    def getSymbolIterator(self) -> ghidra.program.model.symbol.SymbolIterator:
        """
        Get all label symbols
         <p>
         Labels are defined on memory locations.
        @return symbol iterator
        """
        ...

    @overload
    def getSymbolIterator(self, forward: bool) -> ghidra.program.model.symbol.SymbolIterator:
        """
        Get all the symbols defined with program memory.
         <p>
         <b>NOTE:</b> The returned symbols will not include any external symbols defined within the 
         {@link AddressSpace#EXTERNAL_SPACE}.  In addition, all global dynamic label symbols will 
         be omitted.
        @param forward the direction of the iterator, by address
        @return symbol iterator
        """
        ...

    @overload
    def getSymbolIterator(self, searchStr: unicode, caseSensitive: bool) -> ghidra.program.model.symbol.SymbolIterator:
        """
        Get an iterator over all symbols that match the given query
         <p>
         <b>NOTE:</b> The iterator is in the forward direction only and will not return default thunks
         (i.e., thunk function symbol with default source type).
        @param searchStr the query, which may contain * to match any sequence or ? to match a single
                    char
        @param caseSensitive flag to specify whether the search is case sensitive
        @return symbol iterator
        """
        ...

    @overload
    def getSymbolIterator(self, startAddr: ghidra.program.model.address.Address, forward: bool) -> ghidra.program.model.symbol.SymbolIterator:
        """
        Get all the symbols starting at the specified memory address.
         <p>
         <b>NOTE:</b> The returned symbols will not include any external symbols defined within the 
         {@link AddressSpace#EXTERNAL_SPACE}.  In addition, all global dynamic label symbols will 
         be omitted.
        @param startAddr the starting address
        @param forward true means the iterator is in the forward direction
        @return symbol iterator
        @throws IllegalArgumentException if startAddr is not a memory address
        """
        ...

    @overload
    def getSymbols(self, namespaceID: long) -> ghidra.program.model.symbol.SymbolIterator:
        """
        Get an iterator over all the symbols in the given namespace
         <p>
         <b>NOTE:</b> The resulting iterator will not return default thunks (i.e., thunk function
         symbol with default source type).
        @param namespaceID the namespace ID to search for symbols.
        @return symbol iterator
        """
        ...

    @overload
    def getSymbols(self, name: unicode) -> ghidra.program.model.symbol.SymbolIterator:
        """
        Get all the symbols with the given name
         <p>
         <b>NOTE:</b> The resulting iterator will not return default thunks (i.e., thunk function
         symbol with default source type). It will also not work for default local variables and
         parameters.
        @param name the name of symbols to search for
        @return an iterator over symbols with the given name
        """
        ...

    @overload
    def getSymbols(self, addr: ghidra.program.model.address.Address) -> List[ghidra.program.model.symbol.Symbol]:
        """
        Get all the symbols at the given address.  This method will include a dynamic memory symbol
         if one exists at the specified address.
         <p>
         For a memory address the primary symbol will be returned at array index 0. <b>WARNING!</b>
         Use of this method with non-memory addresses is discouraged.  Example: Variable
         address could be used multiple times by many functions. 
         <p>
         <b>NOTE:</b> unless all the symbols are needed at once, and a dynamic symbol can be ignored,
         consider using {@link #getSymbolsAsIterator(Address)} instead.
        @param addr the address of the symbols
        @return an array, possibly empty, of the symbols at the given address
        @see #getSymbolsAsIterator(Address)
        """
        ...

    @overload
    def getSymbols(self, namespace: ghidra.program.model.symbol.Namespace) -> ghidra.program.model.symbol.SymbolIterator:
        """
        Get an iterator over all the symbols in the given namespace
         <p>
         <b>NOTE:</b> The resulting iterator will not return default thunks (i.e., thunk function
         symbol with default source type).
        @param namespace the namespace to search for symbols
        @return an iterator over the symbols
        @throws IllegalArgumentException if the given parent namespace is from a different program
                     than that of this symbol table
        """
        ...

    @overload
    def getSymbols(self, name: unicode, namespace: ghidra.program.model.symbol.Namespace) -> List[ghidra.program.model.symbol.Symbol]:
        """
        Get a list of all symbols with the given name in the given parent namespace.  If the global
         namespace is specified matches against dynamic label symbols will be included.  
         <p>
         <b>NOTE:</b> If a function namespace is specified default parameter and local variable names 
         will be included.  If an external library or namespace is specified default external 
         label/function symbols will be included.
         <p>
         <b>NOTE:</b> The resulting iterator will not return default thunks (i.e., thunk function
         symbol with default source type).
        @param name the name of the symbols to retrieve
        @param namespace the namespace to search for symbols
        @return a list of symbols which satisfy specified criteria
        @throws IllegalArgumentException if the given parent namespace is from a different program
                 than that of this symbol table
        """
        ...

    @overload
    def getSymbols(self, addressSet: ghidra.program.model.address.AddressSetView, type: ghidra.program.model.symbol.SymbolType, forward: bool) -> ghidra.program.model.symbol.SymbolIterator:
        """
        Get all the symbols of the given type within the given address set.
         <p>
         <b>NOTE:</b> All external symbols will be omiitted unless the full 
         {@link AddressSpace#EXTERNAL_SPACE} range is included within the specified address set
         or a null addressSet is specified.  All global dynamic label symbols will be omitted.
        @param addressSet the address set containing the symbols.  A null value may be specified
         to include all memory and external primary symbols.
        @param type the type of the symbols
        @param forward the direction of the iterator, by address
        @return symbol iterator
        """
        ...

    def getSymbolsAsIterator(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.symbol.SymbolIterator:
        """
        Get an iterator over the symbols at the given address.  Any dynamic symbol at the address
         will be excluded.
         <p>
         Use this instead of {@link #getSymbols(Address)} when you do not need to get all symbols, but
         rather are searching for a particular symbol. This method prevents all symbols at the given
         address from being loaded up front.
        @param addr the address of the symbols
        @return an iterator over the symbols at the given address
        @see #getSymbols(Address)
        """
        ...

    def getUserSymbols(self, addr: ghidra.program.model.address.Address) -> List[ghidra.program.model.symbol.Symbol]:
        """
        Get an array of defined symbols at the given address (i.e., those with database record).  
         Any dynamic memory symbol at the address will be excluded. 
         <p>
         <b>WARNING!</b>
         Use of this method with non-memory addresses is discouraged.  Example: Variable
         address could be used multiple times by many functions. 
         <p>
         <b>NOTE:</b> unless all the symbols are needed at once, consider using 
         {@link #getSymbolsAsIterator(Address)} instead.
        @param addr the address of the symbols
        @return an array, possibly empty, of the symbols
        """
        ...

    def getVariableSymbol(self, name: unicode, function: ghidra.program.model.listing.Function) -> ghidra.program.model.symbol.Symbol:
        """
        Get a symbol that is either a parameter or local variable.
         <p>
         There can be only one because these symbol types have a unique name requirement.
        @param name the name of the variable
        @param function the function to search
        @return a parameter or local variable symbol with the given name
        """
        ...

    def hasLabelHistory(self, addr: ghidra.program.model.address.Address) -> bool:
        """
        Check if there is a history of label changes at the given address
        @param addr the address to check
        @return true if a label history exists for specified address, otherwise false
        """
        ...

    def hasSymbol(self, addr: ghidra.program.model.address.Address) -> bool:
        """
        Check if there exists any symbol at the given address
        @param addr address to check for an existing symbol
        @return true if any symbol exists
        """
        ...

    def hashCode(self) -> int: ...

    def isExternalEntryPoint(self, addr: ghidra.program.model.address.Address) -> bool:
        """
        Check if the given address is an external entry point
        @param addr address to check
        @return true if specified address has been marked as an entry point, otherwise false
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def removeExternalEntryPoint(self, addr: ghidra.program.model.address.Address) -> None:
        """
        Remove an address from the external entry points
        @param addr the address to remove
        """
        ...

    def removeSymbolSpecial(self, sym: ghidra.program.model.symbol.Symbol) -> bool:
        """
        Removes the specified symbol from the symbol table.
         <p>
         If removing any <b>non-function</b> symbol, the behavior will be the same as invoking
         {@link Symbol#delete()} on the symbol. Use of this method for non-function symbols is
         discouraged.
         <p>
         <b>WARNING!</b> If removing a function symbol, the behavior differs from directly invoking
         {@link Symbol#delete()} on the function symbol. When removing a function symbol this method
         has the following behavior:
         <ul>
         <li>If the function is a default symbol (e.g., FUN_12345678) this method has no effect and
         will return false.</li>
         <li>If no other labels exist at the function entry, the function will be renamed to the
         default function name.</li>
         <li>If another label does exist at the function entry point, that label will be removed, and
         the function will be renamed to that label's name.</li>
         </ul>
         <p>
         Any reference bound to a removed symbol will lose that symbol specific binding.
        @param sym the symbol to be removed.
        @return true if a symbol is removed, false if not or in case of failure
        """
        ...

    def scanSymbolsByName(self, startName: unicode) -> ghidra.program.model.symbol.SymbolIterator:
        """
        Scan symbols lexicographically by name
         <p>
         If a symbol with the given start name does not exist, the iterator will start at the first
         symbol following it. This includes only symbols whose addresses are in memory. In particular,
         it excludes external symbols and dynamic symbols, i.e., those generated as a reference
         destination.
        @param startName the starting point
        @return an iterator over the symbols in lexicographical order
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
    def classNamespaces(self) -> java.util.Iterator: ...

    @property
    def definedSymbols(self) -> ghidra.program.model.symbol.SymbolIterator: ...

    @property
    def externalEntryPointIterator(self) -> ghidra.program.model.address.AddressIterator: ...

    @property
    def externalSymbols(self) -> ghidra.program.model.symbol.SymbolIterator: ...

    @property
    def labelHistory(self) -> java.util.Iterator: ...

    @property
    def numSymbols(self) -> int: ...

    @property
    def symbolIterator(self) -> ghidra.program.model.symbol.SymbolIterator: ...