from typing import List
import java.lang


class WeakStore(object):
    """
    Class for storing a weak reference to object instances. Objects of type T can be placed in this 
     store and they will remain there until there are no references to that object. Note 
     that this is not a Set and you can have multiple instances that are "equal" in this store.The 
     main purpose of this store is to be able to get all objects in the store that are still 
     referenced.  This is useful when you need to visit all in use items.   
 
     This class is thread safe.
    """





    def __init__(self): ...



    def add(self, value: object) -> None:
        """
        Adds the given value to the store
        @param value the instance being added to the store
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getValues(self) -> List[object]:
        """
        returns a list of all the objects in this store
        @return a list of all the objects in this store
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def size(self) -> int:
        """
        Returns the number of objects of type T remaining in the store. Those that are remaining
         are either still referenced
        @return the number of objects still in the store that haven't yet been garbage collected
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
    def values(self) -> List[object]: ...