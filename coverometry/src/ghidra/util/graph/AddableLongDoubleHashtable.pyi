from typing import List
import ghidra.util.datastruct
import java.lang


class AddableLongDoubleHashtable(ghidra.util.datastruct.LongDoubleHashtable):
    """
    This class modifies the behavior of LongDoubleHashtable. May add
     to the value stored with the key rather than replacing the value.
    """





    @overload
    def __init__(self): ...

    @overload
    def __init__(self, capacity: int):
        """
        Constructor creates a table with an initial given capacity.  The capacity
         will be adjusted to the next highest prime in the PRIMES table.
        """
        ...



    def add(self, key: long, value: float) -> None:
        """
        Adds the value to the stored value rather than replacing it.
        """
        ...

    def contains(self, key: long) -> bool:
        """
        Return true if the given key is in the hashtable.
        @param key the key whose presence in this map is to be tested.
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def get(self, key: long) -> float:
        """
        Returns the value for the given key.
        @param key the key whose associated value is to be returned.
        @exception NoValueException thrown if there is no value for the given key.
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getKeys(self) -> List[long]:
        """
        Returns an array containing all the long keys.
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def put(self, key: long, value: float) -> None:
        """
        Adds a key/value pair to the hashtable. If the key is already in the table,
         the old value is replaced with the new value.  If the hashtable is already
         full, the hashtable will attempt to approximately double in size
         (it will use a prime number), and all the current entries will
         be rehashed.
        @param key the key to associate with the given value.
        @param value the value to associate with the given key.
        @exception ArrayIndexOutOfBoundsException thrown if the maximum capacity is
         reached.
        """
        ...

    def remove(self, key: long) -> bool:
        """
        Removes a key from the hashtable
        @param key key to be removed from the hashtable.
        @return true if key is found and removed, false otherwise.
        """
        ...

    def removeAll(self) -> None:
        """
        Remove all entries from the hashtable.
        """
        ...

    def size(self) -> int:
        """
        Return the number of key/value pairs stored in the hashtable.
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

