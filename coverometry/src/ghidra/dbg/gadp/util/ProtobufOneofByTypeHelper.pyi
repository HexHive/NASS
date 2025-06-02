import com.google.protobuf
import ghidra.dbg.gadp.util
import java.lang


class ProtobufOneofByTypeHelper(object):








    @staticmethod
    def create(__a0: com.google.protobuf.AbstractMessage, __a1: com.google.protobuf.Message.Builder, __a2: unicode) -> ghidra.dbg.gadp.util.ProtobufOneofByTypeHelper: ...

    def equals(self, __a0: object) -> bool: ...

    def expect(self, __a0: com.google.protobuf.AbstractMessage, __a1: com.google.protobuf.Message) -> com.google.protobuf.Message: ...

    @staticmethod
    def findOneofByName(__a0: com.google.protobuf.Descriptors.Descriptor, __a1: unicode) -> com.google.protobuf.Descriptors.OneofDescriptor: ...

    def getClass(self) -> java.lang.Class: ...

    def getFieldForTypeOf(self, __a0: com.google.protobuf.MessageOrBuilder) -> com.google.protobuf.Descriptors.FieldDescriptor: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @overload
    def set(self, __a0: com.google.protobuf.Message.Builder, __a1: com.google.protobuf.Message) -> None: ...

    @overload
    def set(self, __a0: com.google.protobuf.Message.Builder, __a1: com.google.protobuf.Message.Builder) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

