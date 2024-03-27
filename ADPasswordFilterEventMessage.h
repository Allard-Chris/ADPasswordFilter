 // https://learn.microsoft.com/en-us/windows/win32/eventlog/reporting-an-event 
 // HEADER SECTION
 // The following are the message definitions.
//
//  Values are 32 bit values laid out as follows:
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//  +---+-+-+-----------------------+-------------------------------+
//  |Sev|C|R|     Facility          |               Code            |
//  +---+-+-+-----------------------+-------------------------------+
//
//  where
//
//      Sev - is the severity code
//
//          00 - Success
//          01 - Informational
//          10 - Warning
//          11 - Error
//
//      C - is the Customer code flag
//
//      R - is a reserved bit
//
//      Facility - is the facility code
//
//      Code - is the facility's status code
//
//
// Define the facility codes
//
#define FACILITY_SYSTEM                  0x0
#define FACILITY_RUNTIME                 0x2
#define FACILITY_STUBS                   0x3
#define FACILITY_IO_ERROR_CODE           0x4


//
// Define the severity codes
//
#define STATUS_SEVERITY_SUCCESS          0x0
#define STATUS_SEVERITY_INFORMATIONAL    0x1
#define STATUS_SEVERITY_WARNING          0x2
#define STATUS_SEVERITY_ERROR            0x3


//
// MessageId: REGISTRY_CATEGORY
//
// MessageText:
//
// ADPasswordFilter DLL Registry Events
//
#define REGISTRY_CATEGORY                ((WORD)0x00000001L)

//
// MessageId: IO_CATEGORY
//
// MessageText:
//
// ADPasswordFilter DLL IO Events
//
#define IO_CATEGORY                      ((WORD)0x00000002L)

//
// MessageId: RUNTIME_CATEGORY
//
// MessageText:
//
// ADPasswordFilter DLL Runtime Events
//
#define RUNTIME_CATEGORY                 ((WORD)0x00000003L)

//
// MessageId: MSG_REGISTRY_KEY_READ
//
// MessageText:
//
// Cannot read the registry key '%1' at '%2'.
//
#define MSG_REGISTRY_KEY_READ            ((DWORD)0xC0000100L)

//
// MessageId: MSG_IO_OPEN_FILE
//
// MessageText:
//
// Cannot open the file '%1' or the file is too big.
//
#define MSG_IO_OPEN_FILE                 ((DWORD)0xC0040101L)

//
// MessageId: MSG_RUNTIME_PASSWORD_FORCED
//
// MessageText:
//
// The password, for the account '%1', has not been checked because it was forced by an administrator.
//
#define MSG_RUNTIME_PASSWORD_FORCED      ((DWORD)0x40020102L)

//
// MessageId: MSG_RUNTIME_ERROR
//
// MessageText:
//
// The function stopped prematurely. The associated message is "%1".
//
#define MSG_RUNTIME_ERROR                ((DWORD)0xC0020103L)

//
// MessageId: MSG_RUNTIME_PASSWORD_NOT_COMPLIANT
//
// MessageText:
//
// The password, for the account '%1', is not compliant. Reason returned: "%2".
//
#define MSG_RUNTIME_PASSWORD_NOT_COMPLIANT ((DWORD)0x40020104L)

