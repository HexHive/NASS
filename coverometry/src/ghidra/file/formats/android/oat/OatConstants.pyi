import java.lang


class OatConstants(object):
    DOT_OAT_PATCHES_SECTION_NAME: unicode = u'.oat_patches'
    MAGIC: unicode = u'oat\n'
    OAT_SECTION_NAME: unicode = u'.rodata'
    OAT_VERSION_007: unicode = u'007'
    OAT_VERSION_039: unicode = u'039'
    OAT_VERSION_045: unicode = u'045'
    OAT_VERSION_051: unicode = u'051'
    OAT_VERSION_064: unicode = u'064'
    OAT_VERSION_079: unicode = u'079'
    OAT_VERSION_088: unicode = u'088'
    OAT_VERSION_124: unicode = u'124'
    OAT_VERSION_126: unicode = u'126'
    OAT_VERSION_131: unicode = u'131'
    OAT_VERSION_138: unicode = u'138'
    OAT_VERSION_170: unicode = u'170'
    OAT_VERSION_183: unicode = u'183'
    OAT_VERSION_195: unicode = u'195'
    OAT_VERSION_199: unicode = u'199'
    OAT_VERSION_220: unicode = u'220'
    OAT_VERSION_223: unicode = u'223'
    OAT_VERSION_225: unicode = u'225'
    OAT_VERSION_227: unicode = u'227'
    SUPPORTED_VERSIONS: List[unicode] = array(java.lang.String, [u'007', u'039', u'045', u'051', u'064', u'079', u'088', u'124', u'126', u'131', u'138', u'170', u'183', u'195', u'199', u'220', u'223', u'225'])
    SYMBOL_OAT_BSS: unicode = u'oatbss'
    SYMBOL_OAT_BSS_LASTWORD: unicode = u'oatbsslastword'
    SYMBOL_OAT_BSS_METHODS: unicode = u'oatbssmethods'
    SYMBOL_OAT_BSS_ROOTS: unicode = u'oatbssroots'
    SYMBOL_OAT_DATA: unicode = u'oatdata'
    SYMBOL_OAT_DATA_BIMGRELRO: unicode = u'oatdatabimgrelro'
    SYMBOL_OAT_DATA_BIMGRELRO_LASTWORD: unicode = u'oatdatabimgrelrolastword'
    SYMBOL_OAT_DEX: unicode = u'oatdex'
    SYMBOL_OAT_DEX_LASTWORD: unicode = u'oatdexlastword'
    SYMBOL_OAT_EXEC: unicode = u'oatexec'
    SYMBOL_OAT_LASTWORD: unicode = u'oatlastword'
    kApexVersionsKey: unicode = u'apex-versions'
    kBootClassPathChecksumsKey: unicode = u'bootclasspath-checksums'
    kBootClassPathKey: unicode = u'bootclasspath'
    kClassPathKey: unicode = u'classpath'
    kCompilationReasonKey: unicode = u'compilation-reason'
    kCompilerFilter: unicode = u'compiler-filter'
    kConcurrentCopying: unicode = u'concurrent-copying'
    kDebuggableKey: unicode = u'debuggable'
    kDex2OatCmdLineKey: unicode = u'dex2oat-cmdline'
    kDex2OatHostKey: unicode = u'dex2oat-host'
    kFalseValue: unicode = u'false'
    kHasPatchInfoKey: unicode = u'has-patch-info'
    kImageLocationKey: unicode = u'image-location'
    kNativeDebuggableKey: unicode = u'native-debuggable'
    kPicKey: unicode = u'pic'
    kRequiresImage: unicode = u'requires-image'
    kTrueValue: unicode = u'true'
    oat_version_008: unicode = u'008'
    oat_version_083: unicode = u'083'
    oat_version_114: unicode = u'114'
    oat_version_125: unicode = u'125'
    oat_version_132: unicode = u'132'
    oat_version_135: unicode = u'135'
    oat_version_139: unicode = u'139'
    oat_version_140: unicode = u'140'
    oat_version_141: unicode = u'141'
    oat_version_146: unicode = u'146'
    oat_version_147: unicode = u'147'
    oat_version_166: unicode = u'166'
    oat_version_197: unicode = u'197'



    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def isSupportedVersion(__a0: unicode) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

