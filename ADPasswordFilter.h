/**
 * @file ADPasswordFilter.h
 * @author Chris Allard
 * @brief Header for ADPasswordFilter DLL
 * @version 1.0
 * @date 2024-03
 */

#pragma once
#define EXPORT extern "C" __declspec(dllexport)

#include "ADPasswordFilterEventMessage.h"
#include "framework.h"
#include <SubAuth.h>
#include <Windows.h>
#include <stdio.h>
#include <string>
#include <strsafe.h>
#include <winbase.h>

// CONSTANTS
#define REGEDIT_SUBKEY L"SOFTWARE\\ADPasswordFilter\\"
#define REGEDIT_WORDS_FILE_KEY L"WordsDictionaryFile"
#define REGEDIT_PASSWORDS_FILE_KEY L"PasswordsListFile"
#define REGEDIT_DISABLE_WORDS_FILTER_KEY L"isWordsDictionaryFilterDisabled"
#define REGEDIT_DISABLE_PASSWORD_FILTER_KEY L"isPasswordsListFilterDisabled"
#define EVTX_PROVIDER_NAME L"ADPasswordFilter"
#define MAX_FILE_SIZE_BYTE 1048576 // 1048579 Bytes = 1 Mo
#define MAX_WORD_SIZE 64           // nb chacaters, not byte.

/**
 * @brief Function called by the Local Security Authority (LSA) to verify that the password notification DLL is loaded and initialized.
 * Microsoft Documentation: https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nc-ntsecapi-psam_init_notification_routine
 *
 * @fn BOOLEAN InitialiazeChangeNotify(void)
 *
 * @return TRUE when the password filter DLL is initialized.
 *
 * @remarks
 *  - InitializeChangeNotify is called by the Local Security Authority(LSA) to verify that the password notification DLL is loaded and initialized.
 *  - This function must use the __stdcall calling convention, and must be exported by the DLL.
 *  - This function is called only for password filters that are installedand registered on a system.
 *
 */
extern "C" EXPORT BOOLEAN __stdcall InitialiazedChangeNotify(void);

/**
 * @brief Function called after the PasswordFilter function has been called successfully and the new password has been stored.
 * Microsoft Documentation: https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nc-ntsecapi-psam_password_notification_routine
 *
 * @fn NTSTATUS PasswordChangeNotify(PUNICODE_STRING UserName, ULONG RelativeId, PUNICODE_STRING NewPassword)
 *
 * @return STATUS_SUCCESS indicates the password of the user was changed, or that the values of both the UserName and NewPassword parameters are NULL.
 *
 * @param[in] UserName The account name of the user whose password changed.
 * If the values of this parameter and the NewPassword parameter are NULL, this function should return STATUS_SUCCESS.
 * @param[in] RelativeId The relative identifier of the user specified in UserName.
 * Relative Identifier: (RID) The portion of a security identifier (SID) that identifies a user or group in relation to the authority that issued the SID.
 * @param[in] NewPassword A new plaintext password for the user specified in UserName.
 * When you have finished using the password, clear the information by calling the SecureZeroMemory function.
 * If the values of this parameter and the NewPassword parameter are NULL, this function should return STATUS_SUCCESS.
 *
 * @remarks
 *  - The PasswordChangeNotify function is called after the PasswordFilter function has been called successfully and the new password has been stored.
 *  - This function must use the __stdcall calling convention, and must be exported by the DLL.
 *  - When the PasswordChangeNotify routine is running, processing is blocked until the routine is finished. When appropriate, move any lengthy processing to a separated thread
 * prior to returning from this routine.
 *  - This function is called only for password filters that are installed and registered on the system.
 *
 */
extern "C" EXPORT NTSTATUS __stdcall PasswordChangeNotify(PUNICODE_STRING UserName, ULONG RelativeId, PUNICODE_STRING NewPassword);

/**
 * @brief Function called when a password change is requested. This is the function that contains the logic to determine if a password is compliant or not.
 * Microsoft Documentation: https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nc-ntsecapi-psam_password_filter_routine
 *
 * @fn BOOLEAN PasswordFilter(PUNICODE_STRING AccountName, PUNICODE_STRING FullName, PUNICODE_STRING Password, BOOLEAN SetOperation)
 *
 * @returns
 *  - TRUE if the new password is valid with respect to the password policy implemented in the password filter DLL. When TRUE is returned, the local Security Authority (LSA)
 * continues to evaluate the password by callin any other password filters installed on the system.
 *  - FALSE if the new password is not valid with respect to the password policy implemented in the password filter DLL.
 * When FALSE is returned, the LSA returns the ERROR_ILL_FORMED_PASSWORD (1324) status code to the source of the password change request.
 *
 * @param[in] AccountName pointer to a UNICODE_STRING that represents the name of the user whose password changed.
 * @param[in] FullName pointer to a UNICODE_STRING that represents the full name of the user whose password changed.
 * @param[in] Password pointer to a UNICODE_STRING that represents the new plaintext password. when you have finished using the password, clear it from memory by calling the SecureZeroMemory function.
 * @param[in] SetOperation TRUE if the password was set rather than changed.
 *
 * @remarks
 *  - Password change requests may be made when users specify a new password, accounts are created and when administrators override a password.
 *  - This function must use the __stdcall calling convention, and must be exported by the DLL.
 *  - When the PasswordChangeNotify routine is running, processing is blocked until the routine is finished. When appropriate, move any lengthy processing to a separated thread
 * prior to returning from this routine.
 *  - This function is called only for password filters that are installed and registered on the system
 */
extern "C" EXPORT BOOLEAN __stdcall PasswordFilter(PUNICODE_STRING AccountName, PUNICODE_STRING FullName, PUNICODE_STRING Password, BOOLEAN SetOperation);

/**
 * @brief Function to read strings from the register.
 * Microsoft Documentation: https://learn.microsoft.com/en-us/archive/msdn-magazine/2017/may/c-use-modern-c-to-access-the-windows-registry
 *
 * @param hKey a handle to an open registry key.
 * @param subKey the path of a registry key relative to the key specified by the hkey parameter. The registry value will be retrieved from this subkey.
 * @param value the name of the registry value.
 *
 * @return std::wstring return the string value at the registry key. In case of error, return an empty string.
 */
std::wstring RegGetString(HKEY hKey, const std::wstring& subKey, const std::wstring& value);

/**
 * @brief Function to read an unsigned 32 bits value from a registry key.
 * Microsoft Documentation: https://learn.microsoft.com/en-us/archive/msdn-magazine/2017/may/c-use-modern-c-to-access-the-windows-registry
 *
 * @param hKey a handle to an open registry key.
 * @param subKey the path of a registry key relative to the key specified by the hkey parameter. The registry value will be retrieved from this subkey.
 * @param value the name of the registry value.
 * @return DWORD return the value at the registry key. In our case, we only must read a 0 (FALSE) or 1 (TRUE).
 * So, if we can't read the value (RegGetValue return an error), we return the value 2. It's an unexpected value in our case.
 */
DWORD RegGetDword(HKEY hKey, const std::wstring& subKey, const std::wstring& value);

/**
 * @brief Function to control and open a file.
 *
 * @param filename the name of the file we want to access.
 *
 * @return FILE* return a pointer to the opened file or nullptr.
 */
FILE* secure_wfopen_s(const wchar_t* filename);

/**
 * @brief Function to convert UPPERCASE caracters to lowercase.
 *
 * @param string string we want to convert with or without UPPERCASE caracters.
 * @return wchar_t* string with only lowercase caracters.
 */
wchar_t* ToLowerString(wchar_t* string);
