import ghidra.app.util.bin.format.golang
import ghidra.program.model.lang
import java.lang


class GoRegisterInfoManager(object):
    """
    XML config file format:
 
     	golang>
     		register_info versions="V1_17,V1_18">
     			int_registers list="RAX,RBX,RCX,RDI,RSI,R8,R9,R10,R11"/>
     			float_registers list="XMM0,XMM1,XMM2,XMM3,XMM4,XMM5,XMM6,XMM7,XMM8,XMM9,XMM10,XMM11,XMM12,XMM13,XMM14"/>
     			stack initialoffset="8" maxalign="8"/>
     			current_goroutine register="R14"/>
     			zero_register register="XMM15" builtin="true|false"/>
     		/register_info>
     		register_info versions="V1_2">
     			...
     		/register_info>
    	/golang> 
 
    """





    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getInstance() -> ghidra.app.util.bin.format.golang.GoRegisterInfoManager: ...

    def getRegisterInfoForLang(self, lang: ghidra.program.model.lang.Language, goVersion: ghidra.app.util.bin.format.golang.GoVer) -> ghidra.app.util.bin.format.golang.GoRegisterInfo:
        """
        Returns a {@link GoRegisterInfo} instance for the specified {@link Language}.
         <p>
         If the language didn't define golang register info, a generic/empty instance will be
         returned that forces all parameters to be stack allocated.
        @param lang {@link Language}
        @param goVersion {@link GoVer} enum
        @return {@link GoRegisterInfo}, never null
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

