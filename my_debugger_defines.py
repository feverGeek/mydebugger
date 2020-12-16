from ctypes import *


# Map of basic C types to Win32 types
CHAR = c_char
WCHAR = c_wchar
BYTE = c_ubyte
SBYTE = c_byte
WORD = c_ushort
SWORD = c_int16
DWORD = c_ulong
SDWORD = c_int32
QWORD = c_uint64
SQWORD = c_int64
SHORT = c_int16
USHORT = c_uint16
INT = c_int32
UINT = c_uint32
LONG = c_int32
ULONG = c_uint32
LONGLONG = c_int64        # c_longlong
ULONGLONG = c_uint64      # c_ulonglong
LPVOID = c_void_p
LPSTR = c_char_p
LPWSTR = c_wchar_p
INT8 = c_int8
INT16 = c_int16
INT32 = c_int32
INT64 = c_int64
UINT8 = c_uint8
UINT16 = c_uint16
UINT32 = c_uint32
UINT64 = c_uint64
LONG32 = c_int32
LONG64 = c_int64
ULONG32 = c_uint32
ULONG64 = c_uint64
DWORD32 = c_uint32
DWORD64 = c_uint64
BOOL = c_int32
FLOAT = c_float        # not sure on cygwin
DOUBLE = c_double       # not sure on cygwin
UINT_PTR = c_ulong

SIZE_T = c_ulong

# Not really pointers but pointer-sized integers
DWORD_PTR = SIZE_T
ULONG_PTR = SIZE_T
LONG_PTR = SIZE_T

# Other Win32 types, more may be added as needed
PVOID = LPVOID
PPVOID = POINTER(PVOID)
PSTR = LPSTR
PWSTR = LPWSTR
PCHAR = LPSTR
PWCHAR = LPWSTR
LPBYTE = POINTER(BYTE)
LPSBYTE = POINTER(SBYTE)
LPWORD = POINTER(WORD)
LPSWORD = POINTER(SWORD)
LPDWORD = POINTER(DWORD)
LPSDWORD = POINTER(SDWORD)
LPULONG = POINTER(ULONG)
LPLONG = POINTER(LONG)
PDWORD = LPDWORD
PDWORD_PTR = POINTER(DWORD_PTR)
PULONG = LPULONG
PLONG = LPLONG
CCHAR = CHAR
BOOLEAN = BYTE
PBOOL = POINTER(BOOL)
LPBOOL = PBOOL
TCHAR = CHAR      # XXX ANSI by default?
UCHAR = BYTE
DWORDLONG = ULONGLONG
LPDWORD32 = POINTER(DWORD32)
LPULONG32 = POINTER(ULONG32)
LPDWORD64 = POINTER(DWORD64)
LPULONG64 = POINTER(ULONG64)
PDWORD32 = LPDWORD32
PULONG32 = LPULONG32
PDWORD64 = LPDWORD64
PULONG64 = LPULONG64
ATOM = WORD
HANDLE = LPVOID
PHANDLE = POINTER(HANDLE)
LPHANDLE = PHANDLE
HMODULE = HANDLE
HINSTANCE = HANDLE
HTASK = HANDLE
HKEY = HANDLE
PHKEY = POINTER(HKEY)
HDESK = HANDLE
HRSRC = HANDLE
HSTR = HANDLE
HWINSTA = HANDLE
HKL = HANDLE
HDWP = HANDLE
HFILE = HANDLE
HRESULT = LONG
HGLOBAL = HANDLE
HLOCAL = HANDLE
HGDIOBJ = HANDLE
HDC = HGDIOBJ
HRGN = HGDIOBJ
HBITMAP = HGDIOBJ
HPALETTE = HGDIOBJ
HPEN = HGDIOBJ
HBRUSH = HGDIOBJ
HMF = HGDIOBJ
HEMF = HGDIOBJ
HENHMETAFILE = HGDIOBJ
HMETAFILE = HGDIOBJ
HMETAFILEPICT = HGDIOBJ
HWND = HANDLE
NTSTATUS = LONG
PNTSTATUS = POINTER(NTSTATUS)
KAFFINITY = ULONG_PTR
RVA = DWORD
RVA64 = QWORD
WPARAM = DWORD
LPARAM = LPVOID
LRESULT = LPVOID
ACCESS_MASK = DWORD
REGSAM = ACCESS_MASK
PACCESS_MASK = POINTER(ACCESS_MASK)
PREGSAM = POINTER(REGSAM)

# 常量
DEBUG_PROCESS = 0x00000001  # 与父进程公用一个控制台（以子进程的方式运行）
CREATE_NEW_CONSOLE = 0x00000010  # 独占一个控制台（以单独的进程运行）
PROCESS_ALL_ACCESS = 0x001F0FFF
INFINITE = 0xFFFFFFFF
DBG_CONTINUE = 0x00010002

EXCEPTION_MAXIMUM_PARAMETERS = 15

# Standard access rights
DELETE                   = (0x00010000)
READ_CONTROL             = (0x00020000)
WRITE_DAC                = (0x00040000)
WRITE_OWNER              = (0x00080000)
SYNCHRONIZE              = (0x00100000)
STANDARD_RIGHTS_REQUIRED = (0x000F0000)
STANDARD_RIGHTS_READ     = (READ_CONTROL)
STANDARD_RIGHTS_WRITE    = (READ_CONTROL)
STANDARD_RIGHTS_EXECUTE  = (READ_CONTROL)
STANDARD_RIGHTS_ALL      = (0x001F0000)
SPECIFIC_RIGHTS_ALL      = (0x0000FFFF)

# 线程访问权限
THREAD_ALL_ACCESS = 0X0001FFFFF  # 视环境而定

TH32CS_SNAPHEAPLIST = 0x00000001
TH32CS_SNAPPROCESS  = 0x00000002
TH32CS_SNAPTHREAD   = 0x00000004
TH32CS_SNAPMODULE   = 0x00000008
TH32CS_INHERIT      = 0x80000000
TH32CS_SNAPALL      = (TH32CS_SNAPHEAPLIST | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE)


# Debug events
EXCEPTION_DEBUG_EVENT       = 1
CREATE_THREAD_DEBUG_EVENT   = 2
CREATE_PROCESS_DEBUG_EVENT  = 3
EXIT_THREAD_DEBUG_EVENT     = 4
EXIT_PROCESS_DEBUG_EVENT    = 5
LOAD_DLL_DEBUG_EVENT        = 6
UNLOAD_DLL_DEBUG_EVENT      = 7
OUTPUT_DEBUG_STRING_EVENT   = 8
RIP_EVENT                   = 9


# Debug status codes (ContinueDebugEvent)
DBG_EXCEPTION_HANDLED           = 0x00010001
DBG_CONTINUE                    = 0x00010002
DBG_REPLY_LATER                 = 0x40010001
DBG_UNABLE_TO_PROVIDE_HANDLE    = 0x40010002
DBG_TERMINATE_THREAD            = 0x40010003
DBG_TERMINATE_PROCESS           = 0x40010004
DBG_CONTROL_C                   = 0x40010005
DBG_PRINTEXCEPTION_C            = 0x40010006
DBG_RIPEXCEPTION                = 0x40010007
DBG_CONTROL_BREAK               = 0x40010008
DBG_COMMAND_EXCEPTION           = 0x40010009
DBG_EXCEPTION_NOT_HANDLED       = 0x80010001
DBG_NO_STATE_CHANGE             = 0xC0010001
DBG_APP_NOT_IDLE                = 0xC0010002


# Status codes
STATUS_WAIT_0                   = 0x00000000
STATUS_ABANDONED_WAIT_0         = 0x00000080
STATUS_USER_APC                 = 0x000000C0
STATUS_TIMEOUT                  = 0x00000102
STATUS_PENDING                  = 0x00000103
STATUS_SEGMENT_NOTIFICATION     = 0x40000005
STATUS_GUARD_PAGE_VIOLATION     = 0x80000001
STATUS_DATATYPE_MISALIGNMENT    = 0x80000002
STATUS_BREAKPOINT               = 0x80000003
STATUS_SINGLE_STEP              = 0x80000004
STATUS_INVALID_INFO_CLASS       = 0xC0000003
STATUS_ACCESS_VIOLATION         = 0xC0000005
STATUS_IN_PAGE_ERROR            = 0xC0000006
STATUS_INVALID_HANDLE           = 0xC0000008
STATUS_NO_MEMORY                = 0xC0000017
STATUS_ILLEGAL_INSTRUCTION      = 0xC000001D
STATUS_NONCONTINUABLE_EXCEPTION = 0xC0000025
STATUS_INVALID_DISPOSITION      = 0xC0000026
STATUS_ARRAY_BOUNDS_EXCEEDED    = 0xC000008C
STATUS_FLOAT_DENORMAL_OPERAND   = 0xC000008D
STATUS_FLOAT_DIVIDE_BY_ZERO     = 0xC000008E
STATUS_FLOAT_INEXACT_RESULT     = 0xC000008F
STATUS_FLOAT_INVALID_OPERATION  = 0xC0000090
STATUS_FLOAT_OVERFLOW           = 0xC0000091
STATUS_FLOAT_STACK_CHECK        = 0xC0000092
STATUS_FLOAT_UNDERFLOW          = 0xC0000093
STATUS_INTEGER_DIVIDE_BY_ZERO   = 0xC0000094
STATUS_INTEGER_OVERFLOW         = 0xC0000095
STATUS_PRIVILEGED_INSTRUCTION   = 0xC0000096
STATUS_STACK_OVERFLOW           = 0xC00000FD
STATUS_CONTROL_C_EXIT           = 0xC000013A
STATUS_FLOAT_MULTIPLE_FAULTS    = 0xC00002B4
STATUS_FLOAT_MULTIPLE_TRAPS     = 0xC00002B5
STATUS_REG_NAT_CONSUMPTION      = 0xC00002C9
STATUS_SXS_EARLY_DEACTIVATION   = 0xC015000F
STATUS_SXS_INVALID_DEACTIVATION = 0xC0150010

STATUS_STACK_BUFFER_OVERRUN     = 0xC0000409
STATUS_WX86_BREAKPOINT          = 0x4000001F
STATUS_HEAP_CORRUPTION          = 0xC0000374

STATUS_POSSIBLE_DEADLOCK        = 0xC0000194

STATUS_UNWIND_CONSOLIDATE       = 0x80000029


# Exception codes
EXCEPTION_ACCESS_VIOLATION          = STATUS_ACCESS_VIOLATION
EXCEPTION_ARRAY_BOUNDS_EXCEEDED     = STATUS_ARRAY_BOUNDS_EXCEEDED
EXCEPTION_BREAKPOINT                = STATUS_BREAKPOINT
EXCEPTION_DATATYPE_MISALIGNMENT     = STATUS_DATATYPE_MISALIGNMENT
EXCEPTION_FLT_DENORMAL_OPERAND      = STATUS_FLOAT_DENORMAL_OPERAND
EXCEPTION_FLT_DIVIDE_BY_ZERO        = STATUS_FLOAT_DIVIDE_BY_ZERO
EXCEPTION_FLT_INEXACT_RESULT        = STATUS_FLOAT_INEXACT_RESULT
EXCEPTION_FLT_INVALID_OPERATION     = STATUS_FLOAT_INVALID_OPERATION
EXCEPTION_FLT_OVERFLOW              = STATUS_FLOAT_OVERFLOW
EXCEPTION_FLT_STACK_CHECK           = STATUS_FLOAT_STACK_CHECK
EXCEPTION_FLT_UNDERFLOW             = STATUS_FLOAT_UNDERFLOW
EXCEPTION_ILLEGAL_INSTRUCTION       = STATUS_ILLEGAL_INSTRUCTION
EXCEPTION_IN_PAGE_ERROR             = STATUS_IN_PAGE_ERROR
EXCEPTION_INT_DIVIDE_BY_ZERO        = STATUS_INTEGER_DIVIDE_BY_ZERO
EXCEPTION_INT_OVERFLOW              = STATUS_INTEGER_OVERFLOW
EXCEPTION_INVALID_DISPOSITION       = STATUS_INVALID_DISPOSITION
EXCEPTION_NONCONTINUABLE_EXCEPTION  = STATUS_NONCONTINUABLE_EXCEPTION
EXCEPTION_PRIV_INSTRUCTION          = STATUS_PRIVILEGED_INSTRUCTION
EXCEPTION_SINGLE_STEP               = STATUS_SINGLE_STEP
EXCEPTION_STACK_OVERFLOW            = STATUS_STACK_OVERFLOW

EXCEPTION_GUARD_PAGE                = STATUS_GUARD_PAGE_VIOLATION
EXCEPTION_INVALID_HANDLE            = STATUS_INVALID_HANDLE
EXCEPTION_POSSIBLE_DEADLOCK         = STATUS_POSSIBLE_DEADLOCK
EXCEPTION_WX86_BREAKPOINT           = STATUS_WX86_BREAKPOINT

CONTROL_C_EXIT                      = STATUS_CONTROL_C_EXIT

DBG_CONTROL_C                       = 0x40010005
MS_VC_EXCEPTION                     = 0x406D1388

PAGE_GUARD = 0x00000100

# 结构体
class STARTUPINFO(Structure):
    _fields_ = [
        ('cb',              DWORD),
        ('lpReserved',      LPSTR),
        ('lpDesktop',       LPSTR),
        ('lpTitle',         LPSTR),
        ('dwX',             DWORD),
        ('dwY',             DWORD),
        ('dwXSize',         DWORD),
        ('dwYSize',         DWORD),
        ('dwXCountChars',   DWORD),
        ('dwYCountChars',   DWORD),
        ('dwFillAttribute', DWORD),
        ('dwFlags',         DWORD),
        ('wShowWindow',     WORD),
        ('cbReserved2',     WORD),
        ('lpReserved2',     LPVOID),    # LPBYTE
        ('hStdInput',       HANDLE),
        ('hStdOutput',      HANDLE),
        ('hStdError',       HANDLE),
    ]


class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ('hProcess',    HANDLE),
        ('hThread',     HANDLE),
        ('dwProcessId', DWORD),
        ('dwThreadId',  DWORD),
    ]


class EXCEPTION_RECORD(Structure):
    pass
PEXCEPTION_RECORD = POINTER(EXCEPTION_RECORD)
EXCEPTION_RECORD._fields_ = [
        ('ExceptionCode',           DWORD),
        ('ExceptionFlags',          DWORD),
        ('ExceptionRecord',         PEXCEPTION_RECORD),
        ('ExceptionAddress',        PVOID),
        ('NumberParameters',        DWORD),
        ('ExceptionInformation',    UINT_PTR * EXCEPTION_MAXIMUM_PARAMETERS),
    ]


class EXCEPTION_DEBUG_INFO(Structure):
    _fields_ = [
        ("ExceptionRecord", EXCEPTION_RECORD),
        ('dwFistChance', DWORD),
    ]


class CREATE_THREAD_DEBUG_INFO(Structure):
    _fields_ = [
        ('hThread',             HANDLE),
        ('lpThreadLocalBase',   LPVOID),
        ('lpStartAddress',      LPVOID),
    ]


class CREATE_PROCESS_DEBUG_INFO(Structure):
    _fields_ = [
        ('hFile',                   HANDLE),
        ('hProcess',                HANDLE),
        ('hThread',                 HANDLE),
        ('lpBaseOfImage',           LPVOID),
        ('dwDebugInfoFileOffset',   DWORD),
        ('nDebugInfoSize',          DWORD),
        ('lpThreadLocalBase',       LPVOID),
        ('lpStartAddress',          LPVOID),
        ('lpImageName',             LPVOID),
        ('fUnicode',                WORD),
    ]


class EXIT_THREAD_DEBUG_INFO(Structure):
    _fields_ = [
        ('dwExitCode',          DWORD),
    ]


class EXIT_PROCESS_DEBUG_INFO(Structure):
    _fields_ = [
        ('dwExitCode',          DWORD),
    ]


class LOAD_DLL_DEBUG_INFO(Structure):
    _fields_ = [
        ('hFile',                   HANDLE),
        ('lpBaseOfDll',             LPVOID),
        ('dwDebugInfoFileOffset',   DWORD),
        ('nDebugInfoSize',          DWORD),
        ('lpImageName',             LPVOID),
        ('fUnicode',                WORD),
    ]


class UNLOAD_DLL_DEBUG_INFO(Structure):
    _fields_ = [
        ('lpBaseOfDll',         LPVOID),
    ]


class OUTPUT_DEBUG_STRING_INFO(Structure):
    _fields_ = [
        ('lpDebugStringData',   LPVOID),    # don't use LPSTR
        ('fUnicode',            WORD),
        ('nDebugStringLength',  WORD),
    ]


class RIP_INFO(Structure):
    _fields_ = [
        ('dwError',             DWORD),
        ('dwType',              DWORD),
    ]


class DEBUG_EVENT_UNION(Union):
    _fields_ = [
        ("Exception",         EXCEPTION_DEBUG_INFO),
        ("CreateThread",      CREATE_THREAD_DEBUG_INFO),
        ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
        ("ExitThread",        EXIT_THREAD_DEBUG_INFO),
        ("ExitProcess",       EXIT_PROCESS_DEBUG_INFO),
        ("LoadDll",           LOAD_DLL_DEBUG_INFO),
        ("UnloadDll",         UNLOAD_DLL_DEBUG_INFO),
        ("DebugString",       OUTPUT_DEBUG_STRING_INFO),
        ("RipInfo",           RIP_INFO),
    ]


class DEBUG_EVENT(Structure):  # 定义DEBUG_EVENT处理事件
    _fields_ = [
        ("dwDebugEventCode", DWORD),  # 调试事件类型
        ("dwProcessId",      DWORD),
        ("dwThreadId",       DWORD),
        ("u",    DEBUG_EVENT_UNION),
    ]


class THREADENTRY32(Structure):
    _fields_ = [
        ('dwSize',             DWORD),
        ('cntUsage',           DWORD),
        ('th32ThreadID',       DWORD),
        ('th32OwnerProcessID', DWORD),
        ('tpBasePri',          DWORD),
        ('tpDeltaPri',         DWORD),
        ('dwFlags',            DWORD),
    ]


# context_i386
SIZE_OF_80387_REGISTERS = 80
MAXIMUM_SUPPORTED_EXTENSION = 512
CONTEXT_i386 = 0x00010000    # this assumes that i386 and
CONTEXT_i486 = 0x00010000    # i486 have identical context records

CONTEXT_CONTROL = (CONTEXT_i386 | 0x00000001)  # SS:SP, CS:IP, FLAGS, BP
CONTEXT_INTEGER = (CONTEXT_i386 | 0x00000002)  # AX, BX, CX, DX, SI, DI
CONTEXT_SEGMENTS = (CONTEXT_i386 | 0x00000004)  # DS, ES, FS, GS
CONTEXT_FLOATING_POINT = (CONTEXT_i386 | 0x00000008)  # 387 state
CONTEXT_DEBUG_REGISTERS = (CONTEXT_i386 | 0x00000010)  # DB 0-3,6,7
CONTEXT_EXTENDED_REGISTERS = (
    CONTEXT_i386 | 0x00000020)  # cpu specific extensions

CONTEXT_FULL = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS)

HW_EXECUTE = 0x00000000
HW_WRITE   = 0x00000001
HW_ACCESS  = 0x00000003


class FLOATING_SAVE_AREA(Structure):
    _fields_ = [
        ('ControlWord',     DWORD),
        ('StatusWord',      DWORD),
        ('TagWord',         DWORD),
        ('ErrorOffset',     DWORD),
        ('ErrorSelector',   DWORD),
        ('DataOffset',      DWORD),
        ('DataSelector',    DWORD),
        ('RegisterArea',    BYTE * SIZE_OF_80387_REGISTERS),
        ('Cr0NpxState',     DWORD),
    ]


class CONTEXT(Structure):
    _fields_ = [
        ("ContextFlags", DWORD),
        ("Dr0", DWORD),
        ("Dr1", DWORD),
        ("Dr2", DWORD),
        ("Dr3", DWORD),
        ("Dr6", DWORD),
        ("Dr7", DWORD),
        ("FloatSave", FLOATING_SAVE_AREA),
        ("SegGs", DWORD),
        ("SegFs", DWORD),
        ("SegEs", DWORD),
        ("SegDs", DWORD),
        ("Edi", DWORD),
        ("Esi", DWORD),
        ("Ebx", DWORD),
        ("Edx", DWORD),
        ("Ecx", DWORD),
        ("Eax", DWORD),
        ("Ebp", DWORD),
        ("Eip", DWORD),
        ("SegCs", DWORD),
        ("EFlags", DWORD),
        ("Esp", DWORD),
        ("SegSs", DWORD),
        ("ExtendedRegisters", BYTE * MAXIMUM_SUPPORTED_EXTENSION),
    ]


class PROC_STRUCT(Structure):
    _fields_ = [
        ("wProcessorArchitecture", WORD),
        ("wReserved", WORD),
    ]


class SYSTEM_INFO_UNION(Union):
    _fields_ = [
        ("dsOemId", DWORD),
        ("sProcStruc", PROC_STRUCT),
    ]


class SYSTEM_INFO(Structure):
    _fields_ = [
        ("uSysInfo", SYSTEM_INFO_UNION),
        ("dwPageSize", DWORD),
        ("lpMinimumApplicationAddress", LPVOID),
        ("lpMaximumApplicationAddress", LPVOID),
        ("dwActiveProcessMask", DWORD),
        ("dwNumberOfProcessors", DWORD),
        ("dwProcessorType", DWORD),
        ("dwAllocationGranularity", DWORD),
        ("wProcessorLevel", WORD),
        ("wProcessorRevision", WORD),
    ]


class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("BaseAddress", PVOID),
        ("AllocationBase", PVOID),
        ("AllocationProtect", DWORD),
        ("RegionSize",SIZE_T),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD),
    ]
