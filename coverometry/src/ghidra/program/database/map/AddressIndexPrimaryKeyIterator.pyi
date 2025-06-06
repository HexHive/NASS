import db
import java.lang


class AddressIndexPrimaryKeyIterator(object, db.DBFieldIterator):
    """
    Long iterator over indexed addresses. The longs are primary keys returned ordered and restrained
     by the address field they contain
    """





    @overload
    def __init__(self):
        """
        Empty iterator constructor
        """
        ...

    @overload
    def __init__(self, table: db.Table, indexCol: int, addrMap: ghidra.program.database.map.AddressMap, atStart: bool):
        """
        Constructs a new AddressIndexPrimaryKeyIterator.
         Memory addresses encoded as Absolute are not included.
        @param table the database table containing indexed addresses.
        @param indexCol the column that contains indexed addresses.
        @param addrMap the address map
        @param atStart if true, iterates forward, otherwise iterates backwards.
        @throws IOException if a database io error occurs.
        """
        ...

    @overload
    def __init__(self, table: db.Table, indexCol: int, addrMap: ghidra.program.database.map.AddressMap, start: ghidra.program.model.address.Address, before: bool):
        """
        Constructs a new AddressIndexPrimaryKeyIterator starting at a given address.
         Memory addresses encoded as Absolute are not included.
        @param table the database table containing indexed addresses.
        @param indexCol the column that contains indexed addresses.
        @param addrMap the address map
        @param start the starting address for the iterator.
        @param before if true, positions the iterator before start, otherwise positions it after start.
        @throws IOException if a database io error occurs.
        """
        ...

    @overload
    def __init__(self, table: db.Table, indexCol: int, addrMap: ghidra.program.database.map.AddressMap, set: ghidra.program.model.address.AddressSetView, atStart: bool):
        """
        Constructs a new AddressIndexPrimaryKeyIterator for a set of addresses.
         Memory addresses encoded as Absolute are not included.
        @param table the database table containing indexed addresses.
        @param indexCol the column that contains indexed addresses.
        @param addrMap the address map
        @param set the set of addresses to iterator over.
        @param atStart if true, iterates forward, otherwise iterates backwards.
        @throws IOException if a database io error occurs.
        """
        ...

    @overload
    def __init__(self, table: db.Table, indexCol: int, addrMap: ghidra.program.database.map.AddressMap, minAddr: ghidra.program.model.address.Address, maxAddr: ghidra.program.model.address.Address, atStart: bool):
        """
        Constructs a new AddressIndexPrimaryKeyIterator for a range of addresses.
         Memory addresses encoded as Absolute are not included.
        @param table the database table containing indexed addresses.
        @param indexCol the column that contains indexed addresses.
        @param addrMap the address map
        @param minAddr the first address in the range to iterate over.
        @param maxAddr the last address in the range to iterator over.
        @param atStart if true, iterates forward, otherwise iterates backwards.
        @throws IOException if a database io error occurs.
        """
        ...



    def delete(self) -> bool: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hasNext(self) -> bool: ...

    def hasPrevious(self) -> bool: ...

    def hashCode(self) -> int: ...

    def next(self) -> db.Field: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def previous(self) -> db.Field: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

