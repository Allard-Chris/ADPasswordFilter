; // https://learn.microsoft.com/en-us/windows/win32/eventlog/reporting-an-event 

; // HEADER SECTION

SeverityNames=(
    Success=0x0:STATUS_SEVERITY_SUCCESS
    Informational=0x1:STATUS_SEVERITY_INFORMATIONAL
    Warning=0x2:STATUS_SEVERITY_WARNING
    Error=0x3:STATUS_SEVERITY_ERROR
)

FacilityNames=(
    System=0x0:FACILITY_SYSTEM
    Runtime=0x2:FACILITY_RUNTIME
    Stubs=0x3:FACILITY_STUBS
    Io=0x4:FACILITY_IO_ERROR_CODE
)

LanguageNames=(English=0x409:MSG00409)

; // The following are the message definitions.

MessageIdTypedef=WORD

MessageId=0x1
SymbolicName=REGISTRY_CATEGORY
Language=English
ADPasswordFilter DLL Registry Events
.

MessageId=0x2
SymbolicName=IO_CATEGORY
Language=English
ADPasswordFilter DLL IO Events
.

MessageId=0x3
SymbolicName=RUNTIME_CATEGORY
Language=English
ADPasswordFilter DLL Runtime Events
.

MessageIdTypedef=DWORD

MessageId=0x100
Severity=Error
Facility=System
SymbolicName=MSG_REGISTRY_KEY_READ
Language=English
Cannot read the registry key '%1' at '%2'.
.

MessageId=0x101
Severity=Error
Facility=Io
SymbolicName=MSG_IO_OPEN_FILE
Language=English
Cannot open the file '%1' or the file is too big.
.

MessageId=0x102
Severity=Informational
Facility=Runtime
SymbolicName=MSG_RUNTIME_PASSWORD_FORCED
Language=English
The password, for the account '%1', has not been checked because it was forced by an administrator.
.

MessageId=0x103
Severity=Error
Facility=Runtime
SymbolicName=MSG_RUNTIME_ERROR
Language=English
The function stopped prematurely. The associated message is "%1".
.

MessageId=0x104
Severity=Informational
Facility=Runtime
SymbolicName=MSG_RUNTIME_PASSWORD_NOT_COMPLIANT
Language=English
The password, for the account '%1', is not compliant. Reason returned: "%2".
.
