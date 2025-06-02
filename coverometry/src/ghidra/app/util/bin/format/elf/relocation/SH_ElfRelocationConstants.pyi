import java.lang


class SH_ElfRelocationConstants(object):
    R_SH_64: int = 254
    R_SH_64_PCREL: int = 255
    R_SH_ALIGN: int = 29
    R_SH_CODE: int = 30
    R_SH_COPY: int = 162
    R_SH_COPY64: int = 193
    R_SH_COUNT: int = 28
    R_SH_DATA: int = 31
    R_SH_DIR10S: int = 48
    R_SH_DIR10SL: int = 50
    R_SH_DIR10SQ: int = 51
    R_SH_DIR10SW: int = 49
    R_SH_DIR16: int = 33
    R_SH_DIR16S: int = 53
    R_SH_DIR32: int = 1
    R_SH_DIR4U: int = 42
    R_SH_DIR4UL: int = 40
    R_SH_DIR4UW: int = 41
    R_SH_DIR5U: int = 45
    R_SH_DIR6S: int = 47
    R_SH_DIR6U: int = 46
    R_SH_DIR8: int = 34
    R_SH_DIR8BP: int = 7
    R_SH_DIR8L: int = 9
    R_SH_DIR8S: int = 39
    R_SH_DIR8SW: int = 38
    R_SH_DIR8U: int = 37
    R_SH_DIR8UL: int = 35
    R_SH_DIR8UW: int = 36
    R_SH_DIR8W: int = 8
    R_SH_DIR8WPL: int = 5
    R_SH_DIR8WPN: int = 3
    R_SH_DIR8WPZ: int = 6
    R_SH_GLOB_DAT: int = 163
    R_SH_GLOB_DAT64: int = 194
    R_SH_GNU_VTENTRY: int = 23
    R_SH_GNU_VTINHERIT: int = 22
    R_SH_GOT10BY4: int = 189
    R_SH_GOT10BY8: int = 191
    R_SH_GOT32: int = 160
    R_SH_GOTOFF: int = 166
    R_SH_GOTOFF_HI16: int = 184
    R_SH_GOTOFF_LOW16: int = 181
    R_SH_GOTOFF_MEDHI16: int = 183
    R_SH_GOTOFF_MEDLOW16: int = 182
    R_SH_GOTPC: int = 167
    R_SH_GOTPC_HI16: int = 188
    R_SH_GOTPC_LOW16: int = 185
    R_SH_GOTPC_MEDHI16: int = 187
    R_SH_GOTPC_MEDLOW16: int = 186
    R_SH_GOTPLT10BY4: int = 190
    R_SH_GOTPLT10BY8: int = 192
    R_SH_GOTPLT32: int = 168
    R_SH_GOTPLT_HI16: int = 176
    R_SH_GOTPLT_LOW16: int = 173
    R_SH_GOTPLT_MEDHI16: int = 175
    R_SH_GOTPLT_MEDLOW16: int = 174
    R_SH_GOT_HI16: int = 172
    R_SH_GOT_LOW16: int = 169
    R_SH_GOT_MEDHI16: int = 171
    R_SH_GOT_MEDLOW16: int = 170
    R_SH_IMMS16: int = 244
    R_SH_IMMU16: int = 245
    R_SH_IMM_HI16: int = 252
    R_SH_IMM_HI16_PCREL: int = 253
    R_SH_IMM_LOW16: int = 246
    R_SH_IMM_LOW16_PCREL: int = 247
    R_SH_IMM_MEDHI16: int = 250
    R_SH_IMM_MEDHI16_PCREL: int = 251
    R_SH_IMM_MEDLOW16: int = 248
    R_SH_IMM_MEDLOW16_PCREL: int = 249
    R_SH_IND12W: int = 4
    R_SH_JMP_SLOT: int = 164
    R_SH_JMP_SLOT64: int = 195
    R_SH_LABEL: int = 32
    R_SH_LOOP_END: int = 11
    R_SH_LOOP_START: int = 10
    R_SH_NONE: int = 0
    R_SH_PLT32: int = 161
    R_SH_PLT_HI16: int = 180
    R_SH_PLT_LOW16: int = 177
    R_SH_PLT_MEDHI16: int = 179
    R_SH_PLT_MEDLOW16: int = 178
    R_SH_PSHA: int = 43
    R_SH_PSHL: int = 44
    R_SH_PT_16: int = 243
    R_SH_REL32: int = 2
    R_SH_RELATIVE: int = 165
    R_SH_RELATIVE64: int = 196
    R_SH_SHMEDIA_CODE: int = 242
    R_SH_SWITCH16: int = 25
    R_SH_SWITCH32: int = 26
    R_SH_SWITCH8: int = 24
    R_SH_TLS_DTPMOD32: int = 149
    R_SH_TLS_DTPOFF32: int = 150
    R_SH_TLS_GD_32: int = 144
    R_SH_TLS_IE_32: int = 147
    R_SH_TLS_LDO_32: int = 146
    R_SH_TLS_LD_32: int = 145
    R_SH_TLS_LE_32: int = 148
    R_SH_TLS_TPOFF32: int = 151
    R_SH_USES: int = 27



    def __init__(self): ...



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

