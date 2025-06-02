from typing import List
import ghidra.app.plugin.core.function.editor
import ghidra.program.model.data
import ghidra.program.model.listing
import java.lang


class FunctionEditorModel(object):
    PARSING_MODE_STATUS_TEXT: unicode = u'<HTML>&lt;TAB&gt; or &lt;RETURN&gt; to commit edits, &lt;ESC&gt; to abort'



    def __init__(self, __a0: ghidra.app.services.DataTypeManagerService, __a1: ghidra.program.model.listing.Function): ...



    def canCustomizeStorage(self) -> bool: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getParameters(self) -> List[object]: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def removeParameters(self) -> None: ...

    def setCallingConventionName(self, __a0: unicode) -> None: ...

    def setFormalReturnType(self, __a0: ghidra.program.model.data.DataType) -> bool: ...

    def setFunctionData(self, __a0: ghidra.program.model.data.FunctionDefinitionDataType) -> None: ...

    def setModelChanged(self, __a0: bool) -> None: ...

    def setParameterStorage(self, __a0: ghidra.app.plugin.core.function.editor.ParamInfo, __a1: ghidra.program.model.listing.VariableStorage) -> None: ...

    def setReturnStorage(self, __a0: ghidra.program.model.listing.VariableStorage) -> None: ...

    def setSelectedParameterRow(self, __a0: List[int]) -> None: ...

    def setUseCustomizeStorage(self, __a0: bool) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def callingConventionName(self) -> None: ...  # No getter available.

    @callingConventionName.setter
    def callingConventionName(self, value: unicode) -> None: ...

    @property
    def formalReturnType(self) -> None: ...  # No getter available.

    @formalReturnType.setter
    def formalReturnType(self, value: ghidra.program.model.data.DataType) -> None: ...

    @property
    def functionData(self) -> None: ...  # No getter available.

    @functionData.setter
    def functionData(self, value: ghidra.program.model.data.FunctionDefinitionDataType) -> None: ...

    @property
    def modelChanged(self) -> None: ...  # No getter available.

    @modelChanged.setter
    def modelChanged(self, value: bool) -> None: ...

    @property
    def parameters(self) -> List[object]: ...

    @property
    def returnStorage(self) -> None: ...  # No getter available.

    @returnStorage.setter
    def returnStorage(self, value: ghidra.program.model.listing.VariableStorage) -> None: ...

    @property
    def selectedParameterRow(self) -> None: ...  # No getter available.

    @selectedParameterRow.setter
    def selectedParameterRow(self, value: List[int]) -> None: ...

    @property
    def useCustomizeStorage(self) -> None: ...  # No getter available.

    @useCustomizeStorage.setter
    def useCustomizeStorage(self, value: bool) -> None: ...