from typing import List
import ghidra.framework.generic.auth
import java.io
import java.lang


class Password(object, java.io.Closeable):
    """
    Wrapper for a password, held in a char[] array.
 
     #close() an instance will clear the characters of the char array.
    """









    def clone(self) -> ghidra.framework.generic.auth.Password: ...

    def close(self) -> None:
        """
        Clears the password characters by overwriting them with '\0's.
        """
        ...

    @staticmethod
    def copyOf(password: List[int]) -> ghidra.framework.generic.auth.Password:
        """
        Creates a new {@code Password} using a copy the specified characters.
        @param password password characters
        @return new {@code Password} instance
        """
        ...

    def equals(self, obj: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getPasswordChars(self) -> List[int]:
        """
        Returns a reference to the current password characters.
        @return reference to the current password characters
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

    @staticmethod
    def wrap(password: List[int]) -> ghidra.framework.generic.auth.Password:
        """
        Creates a new {@code Password} by wrapping the specified character array.
         <p>
         The new instance will take ownership of the char array, and
         clear it when the instance is {@link #close() closed}.
        @param password password characters
        @return new {@code Password} instance
        """
        ...

    @property
    def passwordChars(self) -> List[int]: ...