import java.lang


class MapItemType(object):
    kDexTypeAnnotationItem: int = 8196
    kDexTypeAnnotationSetItem: int = 4099
    kDexTypeAnnotationSetRefList: int = 4098
    kDexTypeAnnotationsDirectoryItem: int = 8198
    kDexTypeCallSiteIdItem: int = 7
    kDexTypeClassDataItem: int = 8192
    kDexTypeClassDefItem: int = 6
    kDexTypeCodeItem: int = 8193
    kDexTypeDebugInfoItem: int = 8195
    kDexTypeEncodedArrayItem: int = 8197
    kDexTypeFieldIdItem: int = 4
    kDexTypeHeaderItem: int = 0
    kDexTypeHiddenapiClassData: int = -4096
    kDexTypeMapList: int = 4096
    kDexTypeMethodHandleItem: int = 8
    kDexTypeMethodIdItem: int = 5
    kDexTypeProtoIdItem: int = 3
    kDexTypeStringDataItem: int = 8194
    kDexTypeStringIdItem: int = 1
    kDexTypeTypeIdItem: int = 2
    kDexTypeTypeList: int = 4097



    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @overload
    def toString(self) -> unicode: ...

    @overload
    @staticmethod
    def toString(__a0: int) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

