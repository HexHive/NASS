from typing import List
import java.lang


class LayoutAlgorithmNames(object):
    """
    Just a static list of graph layout algorithm names
    """

    BALLOON: unicode = u'Balloon'
    CIRCLE: unicode = u'Circle'
    COMPACT_HIERARCHICAL: unicode = u'Compact Hierarchical'
    COMPACT_RADIAL: unicode = u'Compact Radial'
    FORCED_BALANCED: unicode = u'Force Balanced'
    FORCE_DIRECTED: unicode = u'Force Directed'
    GEM: unicode = u'GEM'
    HIERACHICAL: unicode = u'Hierarchical'
    MIN_CROSS_COFFMAN_GRAHAM: unicode = u'Hierarchical MinCross Coffman Graham'
    MIN_CROSS_LONGEST_PATH: unicode = u'Hierarchical MinCross Longest Path'
    MIN_CROSS_NETWORK_SIMPLEX: unicode = u'Hierarchical MinCross Network Simplex'
    MIN_CROSS_TOP_DOWN: unicode = u'Hierarchical MinCross Top Down'
    RADIAL: unicode = u'Radial'
    VERT_MIN_CROSS_COFFMAN_GRAHAM: unicode = u'Vertical Hierarchical MinCross Coffman Graham'
    VERT_MIN_CROSS_LONGEST_PATH: unicode = u'Vertical Hierarchical MinCross Longest Path'
    VERT_MIN_CROSS_NETWORK_SIMPLEX: unicode = u'Vertical Hierarchical MinCross Network Simplex'
    VERT_MIN_CROSS_TOP_DOWN: unicode = u'Vertical Hierarchical MinCross Top Down'



    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getLayoutAlgorithmNames() -> List[unicode]: ...

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

