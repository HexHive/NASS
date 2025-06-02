import java.lang


class PdbParserConstants(object):
    """
    Program Information options related to PDB data.  All option keys specified
     by this constants file are children of the Program Information options.  Example:
 
        Options options = program.getOptions(Program#PROGRAM_INFO);
        boolean isPdbLoaded = options.getBoolean(#PDB_LOADED, false);
 
    """

    PDB_AGE: unicode = u'PDB Age'
    PDB_FILE: unicode = u'PDB File'
    PDB_GUID: unicode = u'PDB GUID'
    PDB_LOADED: unicode = u'PDB Loaded'
    PDB_SIGNATURE: unicode = u'PDB Signature'
    PDB_VERSION: unicode = u'PDB Version'



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

