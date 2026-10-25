#include "wincompat.h"
#include "service.h"
#include "web/server.h"
#include "log.h"
#include "error.h"
#include <stdio.h>
#include <stdlib.h>

#define SVC_NAME L"lanmgrd"
#define SVC_DISPLAY L"lanmgr 局域网管理系统服务"

static Config *g_cfg;
static Vault *g_vault;

static SERVICE_STATUS_HANDLE g_status_handle;
static SERVICE_STATUS g_status;
static volatile bool g_stopping = false;

static void report_status(DWORD state) {
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwWin32ExitCode = 0;
    g_status.dwServiceSpecificExitCode = 0;
    g_status.dwCheckPoint = 0;
    g_status.dwWaitHint = 0;
    g_status.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
    if (g_status_handle) SetServiceStatus(g_status_handle, &g_status);
}

static DWORD WINAPI svc_control(DWORD ctrl, DWORD evtype, LPVOID evdata, LPVOID ctx) {
    (void)evtype; (void)evdata; (void)ctx;
    if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN) {
        g_stopping = true;
        report_status(SERVICE_STOPPED);
    } else {
        report_status(g_status.dwCurrentState);
    }
    return NO_ERROR;
}

static void WINAPI svc_main(DWORD argc, LPWSTR *argv) {
    (void)argc; (void)argv;
    g_status_handle = RegisterServiceCtrlHandlerExW(SVC_NAME, svc_control, NULL);
    if (!g_status_handle) return;
    report_status(SERVICE_START_PENDING);
    report_status(SERVICE_RUNNING);

    web_server_run(g_cfg, g_vault);

    report_status(SERVICE_STOPPED);
}

int svc_run_as_service(Config *cfg, Vault *vault) {
    g_cfg = cfg;
    g_vault = vault;

    SERVICE_TABLE_ENTRYW table[] = {
        { (LPWSTR)SVC_NAME, svc_main },
        { NULL, NULL },
    };
    if (!StartServiceCtrlDispatcherW(table)) {
        LOGE("StartServiceCtrlDispatcher failed (err=%lu)", GetLastError());
        return E_IO;
    }
    return E_OK;
}

int svc_install(void) {
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) { LOGE("OpenSCManager failed (err=%lu; 需要管理员权限)", GetLastError()); return E_AUTH; }

    wchar_t exe[MAX_PATH];
    GetModuleFileNameW(NULL, exe, MAX_PATH);
    wchar_t cmdline[700];
    swprintf(cmdline, 700, L"\"%s\" --service", exe);

    SC_HANDLE svc = CreateServiceW(scm, SVC_NAME, SVC_DISPLAY,
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
        cmdline, NULL, NULL, NULL, NULL, NULL);
    if (!svc) {
        DWORD e = GetLastError();
        CloseServiceHandle(scm);
        if (e == ERROR_SERVICE_EXISTS) return E_OK;
        LOGE("CreateService failed (err=%lu)", e);
        return E_IO;
    }
    SERVICE_DESCRIPTIONW sd;
    wchar_t desc[] = L"局域网管理系统核心服务（本地 Web 管理界面）";
    sd.lpDescription = desc;
    ChangeServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, &sd);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    LOGI("service installed");
    return E_OK;
}

int svc_uninstall(void) {
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) { LOGE("OpenSCManager failed (err=%lu; 需要管理员权限)", GetLastError()); return E_AUTH; }
    SC_HANDLE svc = OpenServiceW(scm, SVC_NAME, DELETE | SERVICE_STOP);
    if (!svc) { CloseServiceHandle(scm); return E_NOTFOUND; }
    DeleteService(svc);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return E_OK;
}
