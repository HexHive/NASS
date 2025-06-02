from typing import List
import java.lang
import org.jungrapht.visualization.layout.algorithms


class JgtLayoutFactory(object):




    def __init__(self, __a0: java.util.Comparator, __a1: java.util.function.Predicate, __a2: java.util.function.Predicate): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getLayout(self, __a0: unicode) -> org.jungrapht.visualization.layout.algorithms.LayoutAlgorithm: ...

    @staticmethod
    def getSupportedLayoutNames() -> List[object]: ...

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

