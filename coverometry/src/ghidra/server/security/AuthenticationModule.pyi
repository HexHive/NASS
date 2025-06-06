from typing import List
import ghidra.server
import java.lang
import javax.security.auth
import javax.security.auth.callback


class AuthenticationModule(object):
    PASSWORD_CALLBACK_PROMPT: unicode = u'Password'
    USERNAME_CALLBACK_PROMPT: unicode = u'User ID'







    def anonymousCallbacksAllowed(self) -> bool: ...

    def authenticate(self, __a0: ghidra.server.UserManager, __a1: javax.security.auth.Subject, __a2: List[javax.security.auth.callback.Callback]) -> unicode: ...

    @staticmethod
    def createSimpleNamePasswordCallbacks(__a0: bool) -> List[javax.security.auth.callback.Callback]: ...

    def equals(self, __a0: object) -> bool: ...

    def getAuthenticationCallbacks(self) -> List[javax.security.auth.callback.Callback]: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getFirstCallbackOfType(__a0: java.lang.Class, __a1: List[javax.security.auth.callback.Callback]) -> javax.security.auth.callback.Callback: ...

    def hashCode(self) -> int: ...

    def isNameCallbackAllowed(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def authenticationCallbacks(self) -> List[javax.security.auth.callback.Callback]: ...

    @property
    def nameCallbackAllowed(self) -> bool: ...