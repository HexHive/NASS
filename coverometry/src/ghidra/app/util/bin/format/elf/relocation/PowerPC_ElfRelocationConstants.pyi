import java.lang


class PowerPC_ElfRelocationConstants(object):
    PPC_HALF16: int = 65535
    PPC_LOW14: int = 2162684
    PPC_LOW24: int = 67108860
    PPC_WORD30: int = -4
    PPC_WORD32: int = -1
    R_POWERPC_DTPMOD: int = 68
    R_POWERPC_DTPREL: int = 78
    R_POWERPC_DTPREL16: int = 74
    R_POWERPC_DTPREL16_HA: int = 77
    R_POWERPC_DTPREL16_HI: int = 76
    R_POWERPC_DTPREL16_LO: int = 75
    R_POWERPC_GNU_VTENTRY: int = 254
    R_POWERPC_GNU_VTINHERIT: int = 253
    R_POWERPC_GOT_DTPREL16: int = 91
    R_POWERPC_GOT_DTPREL16_HA: int = 94
    R_POWERPC_GOT_DTPREL16_HI: int = 93
    R_POWERPC_GOT_DTPREL16_LO: int = 92
    R_POWERPC_GOT_TLSGD16: int = 79
    R_POWERPC_GOT_TLSGD16_HA: int = 82
    R_POWERPC_GOT_TLSGD16_HI: int = 81
    R_POWERPC_GOT_TLSGD16_LO: int = 80
    R_POWERPC_GOT_TLSLD16: int = 83
    R_POWERPC_GOT_TLSLD16_HA: int = 86
    R_POWERPC_GOT_TLSLD16_HI: int = 85
    R_POWERPC_GOT_TLSLD16_LO: int = 84
    R_POWERPC_GOT_TPREL16: int = 87
    R_POWERPC_GOT_TPREL16_HA: int = 90
    R_POWERPC_GOT_TPREL16_HI: int = 89
    R_POWERPC_GOT_TPREL16_LO: int = 88
    R_POWERPC_IRELATIVE: int = 248
    R_POWERPC_PLTCALL: int = 120
    R_POWERPC_PLTSEQ: int = 119
    R_POWERPC_REL16: int = 249
    R_POWERPC_REL16DX_HA: int = 246
    R_POWERPC_REL16_HA: int = 252
    R_POWERPC_REL16_HI: int = 251
    R_POWERPC_REL16_LO: int = 250
    R_POWERPC_TLS: int = 67
    R_POWERPC_TPREL: int = 73
    R_POWERPC_TPREL16: int = 69
    R_POWERPC_TPREL16_HA: int = 72
    R_POWERPC_TPREL16_HI: int = 71
    R_POWERPC_TPREL16_LO: int = 70
    R_PPC_ADDR14: int = 7
    R_PPC_ADDR14_BRNTAKEN: int = 9
    R_PPC_ADDR14_BRTAKEN: int = 8
    R_PPC_ADDR16: int = 3
    R_PPC_ADDR16_HA: int = 6
    R_PPC_ADDR16_HI: int = 5
    R_PPC_ADDR16_LO: int = 4
    R_PPC_ADDR24: int = 2
    R_PPC_ADDR30: int = 37
    R_PPC_ADDR32: int = 1
    R_PPC_COPY: int = 19
    R_PPC_EMB_BIT_FLD: int = 115
    R_PPC_EMB_MRKREF: int = 110
    R_PPC_EMB_NADDR16: int = 102
    R_PPC_EMB_NADDR16_HA: int = 105
    R_PPC_EMB_NADDR16_HI: int = 104
    R_PPC_EMB_NADDR16_LO: int = 103
    R_PPC_EMB_NADDR32: int = 101
    R_PPC_EMB_RELSDA: int = 116
    R_PPC_EMB_RELSEC16: int = 111
    R_PPC_EMB_RELST_HA: int = 114
    R_PPC_EMB_RELST_HI: int = 113
    R_PPC_EMB_RELST_LO: int = 112
    R_PPC_EMB_SDA21: int = 109
    R_PPC_EMB_SDA2I16: int = 107
    R_PPC_EMB_SDA2REL: int = 108
    R_PPC_EMB_SDAI16: int = 106
    R_PPC_GLOB_DAT: int = 20
    R_PPC_GOT16: int = 14
    R_PPC_GOT16_HA: int = 17
    R_PPC_GOT16_HI: int = 16
    R_PPC_GOT16_LO: int = 15
    R_PPC_JMP_SLOT: int = 21
    R_PPC_LOCAL24PC: int = 23
    R_PPC_NONE: int = 0
    R_PPC_PLT16_HA: int = 31
    R_PPC_PLT16_HI: int = 30
    R_PPC_PLT16_LO: int = 29
    R_PPC_PLT32: int = 27
    R_PPC_PLTREL24: int = 18
    R_PPC_PLTREL32: int = 28
    R_PPC_REL14: int = 11
    R_PPC_REL14_BRNTAKEN: int = 13
    R_PPC_REL14_BRTAKEN: int = 12
    R_PPC_REL24: int = 10
    R_PPC_REL32: int = 26
    R_PPC_RELATIVE: int = 22
    R_PPC_SDAREL16: int = 32
    R_PPC_SECTOFF: int = 33
    R_PPC_SECTOFF_HA: int = 36
    R_PPC_SECTOFF_HI: int = 35
    R_PPC_SECTOFF_LO: int = 34
    R_PPC_TLSGD: int = 95
    R_PPC_TLSLD: int = 96
    R_PPC_TOC16: int = 255
    R_PPC_UADDR16: int = 25
    R_PPC_UADDR32: int = 24
    R_PPC_VLE_HA16A: int = 223
    R_PPC_VLE_HA16D: int = 224
    R_PPC_VLE_HI16A: int = 221
    R_PPC_VLE_HI16D: int = 222
    R_PPC_VLE_LO16A: int = 219
    R_PPC_VLE_LO16D: int = 220
    R_PPC_VLE_REL15: int = 217
    R_PPC_VLE_REL24: int = 218
    R_PPC_VLE_REL8: int = 216
    R_PPC_VLE_SDA21: int = 225
    R_PPC_VLE_SDA21_LO: int = 226
    R_PPC_VLE_SDAREL_HA16A: int = 231
    R_PPC_VLE_SDAREL_HA16D: int = 232
    R_PPC_VLE_SDAREL_HI16A: int = 229
    R_PPC_VLE_SDAREL_HI16D: int = 230
    R_PPC_VLE_SDAREL_LO16A: int = 227
    R_PPC_VLE_SDAREL_LO16D: int = 228







    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

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

