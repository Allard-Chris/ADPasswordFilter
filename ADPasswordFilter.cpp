/**
 * @file ADPasswordFilter.cpp
 * @author Chris ALLARD
 * @brief Implementation of Windows password filter. Microsoft Documentation: https://learn.microsoft.com/en-us/windows/win32/secmgmt/installing-and-registering-a-password-filter-dll
 *
 * @version 1.0
 * @date 2024-03
 */

#include "pch.h"
#include "ADPasswordFilter.h"

// Function called by the Local Security Authority (LSA) to verify that the password notification DLL is loaded and initialized.
extern "C" EXPORT BOOLEAN __stdcall InitialiazedChangeNotify(void) {
  return TRUE; // as we do nothing special to initialize our DLL, we can return TRUE directly.
}

// Function called after the PasswordFilter function has been called successfully and the new password has been stored.
extern "C" EXPORT NTSTATUS __stdcall PasswordChangeNotify(PUNICODE_STRING UserName, ULONG RelativeId, PUNICODE_STRING NewPassword) {
  return TRUE; // this DLL do nothing special when the user has changed his password.
}

// Function to read strings from the registry.
std::wstring RegGetString(HKEY hKey, const std::wstring& subKey, const std::wstring& value) {
  // We request this API to return the desired size for the output string buffer.
  DWORD   dataSize{};
  LSTATUS retCode = RegGetValue(hKey, subKey.c_str(), value.c_str(), RRF_RT_REG_SZ, NULL, NULL, &dataSize);
  if (retCode != ERROR_SUCCESS) return L"";

  // We dynamically allocate a proper size buffer;
  std::wstring data;
  data.resize(dataSize / sizeof(wchar_t));

  // We make a second call to RegGetValue to actually write the string data into the previously allocated buffer.
  retCode = RegGetValue(hKey, subKey.c_str(), value.c_str(), RRF_RT_REG_SZ, NULL, &data[0], &dataSize);
  if (retCode != ERROR_SUCCESS) return L"";

  // We must resize the wstring object according to the size gain with RegGetValue and written into dataSize DWORD.
  DWORD stringLengthInWchars = dataSize / sizeof(wchar_t);
  stringLengthInWchars--; // Exclude the NULL written by the Win32 API
  data.resize(stringLengthInWchars);

  return data;
}

// Function to read an unsigned 32 bits value from a registry key.
DWORD RegGetDword(HKEY hKey, const std::wstring& subKey, const std::wstring& value) {
  DWORD data{};
  DWORD dataSize = sizeof(data);

  // We make a call to RegGetValue to actually get the DWORD from registry.
  LONG retCode = RegGetValue(hKey, subKey.c_str(), value.c_str(), RRF_RT_REG_DWORD, nullptr, &data, &dataSize);
  if (retCode != ERROR_SUCCESS) return 2; // not a value we expect in our program.

  return data;
}

// Function to control and open a file.
FILE* secure_wfopen_s(const wchar_t* filename) {
  long  sizeOfFile = 0;
  FILE* file;

  // Check: we can open the file.
  file = _wfsopen(filename, L"r, ccs = UTF-16LE", _SH_DENYWR);
  if (file == NULL) return nullptr;

  // Check: we controle the size of the file.
  fseek(file, 0, SEEK_END);
  sizeOfFile = ftell(file);
  fseek(file, 0, SEEK_SET);
  if (sizeOfFile > MAX_FILE_SIZE_BYTE) return nullptr;

  // Check that file is UTF-16LE
  BYTE bom[2];
  if (fread(bom, sizeof(bom), 1, file) != 1) return nullptr;
  if (bom[0] != 0xFF && bom[1] != 0xFE) return nullptr;

  return file;
}

// Function to convert UPPERCASE caracters to lowercase.
wchar_t* ToLowerString(wchar_t* string) {
  int i = 0;
  while (string[i]) {
    string[i] = (wchar_t)tolower(string[i]);
    i++;
  }
  return string;
}

// Function called when a password change is requested.
// This is the function that contains the main logic of this DLL and used to determine if a password is compliant or not.
extern "C" EXPORT BOOLEAN __stdcall PasswordFilter(PUNICODE_STRING AccountName, PUNICODE_STRING FullName, PUNICODE_STRING Password, BOOLEAN SetOperation) {

  // By default (it's a design choice), we define that the password is compliant.
  // The value of this boolean will change if one of our tests fails.
  BOOLEAN isPasswordComplex = TRUE;

  std::wstring wordsDictionaryFilename = L"";
  std::wstring passwordsListFilename = L"";
  FILE*        wordsDictionaryFile = nullptr;
  FILE*        passwordsListFile = nullptr;
  DWORD        isWordsDictionaryFilterDisabled = TRUE;
  DWORD        isPasswordsListFilterDisabled = TRUE;
  SIZE_T       newPasswordLength = Password->Length + sizeof(wchar_t); // In Bytes. Add one character for \0
  wchar_t*     newPassword = nullptr;
  wchar_t*     newPasswordLowerCase = nullptr;

  // We will logs activities and errors in Event log. Only non-sensitive information.
  HANDLE  hEventLog = OpenEventLogW(NULL, EVTX_PROVIDER_NAME);
  LPCWSTR pEventInsertStrings[2] = {NULL, NULL};

  // STEP 1: Check SetOperation
  if (SetOperation == TRUE) {
    // We do not filter the new password and return TRUE.
    // The new password was forced, by an administrator (at least I hope so), directly from the AD;
    if (hEventLog) ReportEventW(hEventLog, EVENTLOG_INFORMATION_TYPE, RUNTIME_CATEGORY, MSG_RUNTIME_PASSWORD_FORCED, NULL, 1, 0, (LPCWSTR*)&AccountName->Buffer, NULL);
    goto cleanup;
  }

  // STEP 2: input treatment on password.
  // PUNICODE_STRING. Length doesn't include the terminating NULL (\0) character;
  // PUNICODE_STRING. Buffer is a pointer to a wide-character string that not be null-terminated.
  // @link https://learn.microsoft.com/en-us/windows/win32/api/subauth/ns-subauth-unicode_string
  newPassword = (wchar_t*)malloc(newPasswordLength);
  newPasswordLowerCase = (wchar_t*)malloc(newPasswordLength);
  if ((newPassword == NULL) || (newPasswordLowerCase == NULL)) // malloc error.
  {
    if (hEventLog) {
      pEventInsertStrings[0] = L"memory allocation failure";
      ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, RUNTIME_CATEGORY, MSG_RUNTIME_ERROR, NULL, 1, 0, (LPCWSTR*)pEventInsertStrings, NULL);
    }
    goto cleanup;
  }

  // StringCbCopyExW add the Null character at the end.
  if ((StringCbCopyExW(newPassword, newPasswordLength, Password->Buffer, NULL, NULL, STRSAFE_FILL_BEHIND_NULL) != S_OK) || (StringCbCopyExW(newPasswordLowerCase, newPasswordLength, Password->Buffer, NULL, NULL, STRSAFE_FILL_BEHIND_NULL) != S_OK)) {
    if (hEventLog) {
      pEventInsertStrings[0] = L"string copy failure";
      ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, RUNTIME_CATEGORY, MSG_RUNTIME_ERROR, NULL, 1, 0, (LPCWSTR*)pEventInsertStrings, NULL);
    }
    goto cleanup;
  }

  ToLowerString(newPasswordLowerCase); // Can only lower ANSI characters (because it's a simple subtraction).

  // STEP 3: Check values in the registry.
  isWordsDictionaryFilterDisabled = RegGetDword(HKEY_LOCAL_MACHINE, REGEDIT_SUBKEY, REGEDIT_DISABLE_WORDS_FILTER_KEY);
  isPasswordsListFilterDisabled = RegGetDword(HKEY_LOCAL_MACHINE, REGEDIT_SUBKEY, REGEDIT_DISABLE_PASSWORD_FILTER_KEY);

  if (isWordsDictionaryFilterDisabled == 2 || isPasswordsListFilterDisabled == 2) // Cannot read value from registry.
  {
    if (hEventLog) {
      pEventInsertStrings[0] = (isWordsDictionaryFilterDisabled == 2) ? REGEDIT_DISABLE_WORDS_FILTER_KEY : REGEDIT_DISABLE_PASSWORD_FILTER_KEY;
      pEventInsertStrings[1] = REGEDIT_SUBKEY;
      ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_CATEGORY, MSG_REGISTRY_KEY_READ, NULL, 2, 0, (LPCWSTR*)pEventInsertStrings, NULL);
    }
    goto cleanup;
  }

  // STEP 4: filter password based on prohibited words in a dictionary.
  if (isWordsDictionaryFilterDisabled == 0) {
    // Retrieves the values of the parameters in the registry, set by the administrator.
    wordsDictionaryFilename = RegGetString(HKEY_LOCAL_MACHINE, REGEDIT_SUBKEY, REGEDIT_WORDS_FILE_KEY);

    // Check: we make sure that we have been able to read the values in the registry.
    if (wordsDictionaryFilename.empty()) {
      if (hEventLog) {
        pEventInsertStrings[0] = REGEDIT_WORDS_FILE_KEY;
        pEventInsertStrings[1] = REGEDIT_SUBKEY;
        ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_CATEGORY, MSG_REGISTRY_KEY_READ, NULL, 2, 0, (LPCWSTR*)pEventInsertStrings, NULL);
      }
      goto cleanup;
    }

    // Open file.
    wordsDictionaryFile = secure_wfopen_s(wordsDictionaryFilename.c_str());
    if (!(wordsDictionaryFile)) {
      if (hEventLog) {
        pEventInsertStrings[0] = wordsDictionaryFilename.c_str();
        ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, IO_CATEGORY, MSG_IO_OPEN_FILE, NULL, 1, 0, (LPCWSTR*)pEventInsertStrings, NULL);
      }
      goto cleanup;
    }

    // Loop on each words.
    wchar_t      word[MAX_WORD_SIZE];
    unsigned int wordLength;
    while (fgetws(word, MAX_WORD_SIZE, wordsDictionaryFile) != NULL) {
      // In case of empty line in file.
      if (word[0] == L'\n') { continue; }

      // Convert Line Feed (\n) to end of string (\0).
      wordLength = static_cast<unsigned int>(wcsnlen_s(word, MAX_WORD_SIZE));
      if ((wordLength > 0) && (wordLength < MAX_WORD_SIZE)) {
        if (word[wordLength - 1] == L'\n') { word[wordLength - 1] = L'\0'; }
      } else // buffer error
      {
        if (hEventLog) {
          pEventInsertStrings[0] = L"buffer error in wordsDictionary loop.";
          ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, RUNTIME_CATEGORY, MSG_RUNTIME_ERROR, NULL, 1, 0, (LPCWSTR*)pEventInsertStrings, NULL);
        }
        isPasswordComplex = FALSE;
        goto cleanup;
      }

      ToLowerString((wchar_t*)&word);
      if (wcsstr(newPasswordLowerCase, word) != NULL) {
        if (hEventLog) {
          pEventInsertStrings[0] = AccountName->Buffer;
          pEventInsertStrings[1] = L"The password contains a forbidden word.";
          ReportEventW(hEventLog, EVENTLOG_INFORMATION_TYPE, RUNTIME_CATEGORY, MSG_RUNTIME_PASSWORD_NOT_COMPLIANT, NULL, 2, 0, (LPCWSTR*)pEventInsertStrings, NULL);
        }
        isPasswordComplex = FALSE;
        goto cleanup;
      }
    }
  }

  // STEP 5: filter password based on prohibited passwords.
  if (isPasswordsListFilterDisabled == 0) {
    // Retrieves the values of the parameters entered in the registry, by the administrator, during installation of this DLL.
    passwordsListFilename = RegGetString(HKEY_LOCAL_MACHINE, REGEDIT_SUBKEY, REGEDIT_PASSWORDS_FILE_KEY);

    // Check: we make sure that we have been able to read the values in the register.
    if (passwordsListFilename.empty()) {
      if (hEventLog) {
        pEventInsertStrings[0] = REGEDIT_PASSWORDS_FILE_KEY;
        pEventInsertStrings[1] = REGEDIT_SUBKEY;
        ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, REGISTRY_CATEGORY, MSG_REGISTRY_KEY_READ, NULL, 2, 0, (LPCWSTR*)pEventInsertStrings, NULL);
      }
      goto cleanup;
    }

    // Open file.
    passwordsListFile = secure_wfopen_s(passwordsListFilename.c_str());
    if (!(passwordsListFile)) {
      if (hEventLog) {
        pEventInsertStrings[0] = passwordsListFilename.c_str();
        ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, IO_CATEGORY, MSG_IO_OPEN_FILE, NULL, 1, 0, (LPCWSTR*)pEventInsertStrings, NULL);
      }
      goto cleanup;
    }

    // Loop on each password.
    wchar_t      prohibitedPassword[MAX_WORD_SIZE];
    unsigned int prohibitedPasswordLength;
    while (fgetws(prohibitedPassword, MAX_WORD_SIZE, passwordsListFile) != NULL) {
      // In case of empty line in file.
      if (prohibitedPassword[0] == L'\n') { continue; }

      // Convert Line Feed (\n) to end of string (\0).
      prohibitedPasswordLength = static_cast<unsigned int>(wcsnlen_s(prohibitedPassword, MAX_WORD_SIZE));
      if ((prohibitedPasswordLength > 0) && (prohibitedPasswordLength < MAX_WORD_SIZE)) {
        if (prohibitedPassword[prohibitedPasswordLength - 1] == L'\n') { prohibitedPassword[prohibitedPasswordLength - 1] = L'\0'; }
      } else // buffer error
      {
        if (hEventLog) {
          pEventInsertStrings[0] = L"buffer error in prohibitedPassword loop.";
          ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, RUNTIME_CATEGORY, MSG_RUNTIME_ERROR, NULL, 1, 0, (LPCWSTR*)pEventInsertStrings, NULL);
        }
        isPasswordComplex = FALSE;
        goto cleanup;
      }

      if (wcsstr(newPassword, prohibitedPassword) != NULL) {
        if (hEventLog) {
          pEventInsertStrings[0] = AccountName->Buffer;
          pEventInsertStrings[1] = L"This password is a prohibited one.";
          ReportEventW(hEventLog, EVENTLOG_INFORMATION_TYPE, RUNTIME_CATEGORY, MSG_RUNTIME_PASSWORD_NOT_COMPLIANT, NULL, 2, 0, (LPCWSTR*)pEventInsertStrings, NULL);
        }
        isPasswordComplex = FALSE;
        goto cleanup;
      }
    }
  }

  // Step 6: end, go cleanup.
  goto cleanup;

cleanup:
  // Cleanup all pointers, buffers, ect...
  // clear properly all memories allocated by the code to store and process the
  // password We must use SecureZeroMemory to ensure that data will be
  // overwritten promptly, before freeing the memory;
  if (newPassword != nullptr) {
    SecureZeroMemory(newPassword, newPasswordLength);
    free(newPassword);
  }

  if (newPasswordLowerCase != nullptr) {
    SecureZeroMemory(newPasswordLowerCase, newPasswordLength);
    free(newPasswordLowerCase);
  }

  if (wordsDictionaryFile != nullptr) fclose(wordsDictionaryFile);

  if (passwordsListFile != nullptr) fclose(passwordsListFile);

  if (hEventLog != nullptr) DeregisterEventSource(hEventLog);

  return isPasswordComplex;
}

// An optional entry point into a dynamic-link library (DLL). When the system starts or terminates a process or thread, it calls the entry-point function for each loaded DLL using the first thread of the process.
// Microsoft Documentation: https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
  switch (ul_reason_for_call) {
  case DLL_PROCESS_ATTACH:
  case DLL_THREAD_ATTACH:
  case DLL_THREAD_DETACH:
  case DLL_PROCESS_DETACH:
    break;
  }
  return TRUE;
}