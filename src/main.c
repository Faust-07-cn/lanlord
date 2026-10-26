#include "wincompat.h"
#include <shellapi.h>
#include "core/config.h"
#include "core/log.h"
#include "core/util.h"
#include "core/error.h"
#include "core/jobs.h"
#include "net/topo.h"
#include "sec/vault.h"
#include "sec/risk.h"
#include "sec/audit.h"
#include "exec/exec.h"
#include "agent/agent.h"
#include "agent/tools.h"
#include "agent/provider.h"
#include "agent/vendors.h"
#include "sec/keystore.h"
#include "web/server.h"
#include "svc/service.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define LANMGR_VERSION "0.1.0"

static void usage(const char *prog) {
    printf("lanlord %s - Windows 局域网管理系统\n\n", LANMGR_VERSION);
    printf("用法: %s <命令> [参数]\n\n命令:\n", prog);
    printf("  --help             显示本帮助\n");
    printf("  --version          显示版本号\n");
    printf("  --discover         扫描并打印局域网拓扑 JSON 后退出\n");
    printf("  --demo             启动 Web 演示并打开浏览器\n");
    printf("  --serve            仅启动 Web 服务(无浏览器/服务模式)\n");
    printf("  --service-install  注册 Windows 服务(需管理员)\n");
    printf("  --service-uninstall 删除 Windows 服务(需管理员)\n");
    printf("  --cred-ls          列出已保存凭据（仅标签/目标，不含密码）\n");
    printf("  --cred-add <label> <type> <target> <username> <secret>  保存凭据(DPAPI加密)\n");
    printf("  --cred-del <id>    删除指定凭据\n");
    printf("  --cred-get <id>    读取凭据（开发自测，打印后即零化）\n");
    printf("  --risk-test        风险确认流程自测\n");
}

static DWORD WINAPI open_browser(LPVOID p) {
    Sleep(1500);
    ShellExecuteA(NULL, "open", (const char *)p, NULL, NULL, SW_SHOWNORMAL);
    free(p);
    return 0;
}

static CredType parse_type(const char *s) {
    if (!strcmp(s, "ssh")) return CRED_SSH;
    if (!strcmp(s, "winrm")) return CRED_WINRM;
    if (!strcmp(s, "http")) return CRED_HTTP;
    if (!strcmp(s, "apitoken")) return CRED_APITOKEN;
    return CRED_SSH;
}

int main(int argc, char **argv) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    /* Helper used by OpenSSH (SSH_ASKPASS) to reply with the password. */
    if (argc >= 2 && !strcmp(argv[1], "--askpass")) {
        const char *pw = getenv("LANMGR_ASKPASS_PW");
        if (pw) printf("%s\n", pw);
        else printf("\n");
        return 0;
    }

    Config cfg;
    config_load(&cfg, "config.json");
    log_init(cfg.log_path, LOG_INFO);
    audit_init(cfg.audit_path);
    risk_init();

    if (argc < 2) { usage(argv[0]); return 1; }

    const char *cmd = argv[1];
    if (!strcmp(cmd, "--help") || !strcmp(cmd, "-h")) { usage(argv[0]); return 0; }
    if (!strcmp(cmd, "--version") || !strcmp(cmd, "-v")) { printf("lanlord %s\n", LANMGR_VERSION); return 0; }

    LOGI("lanlord %s cmd=%s", LANMGR_VERSION, cmd);

    if (!strcmp(cmd, "--demo") || !strcmp(cmd, "--serve")) {
        Vault v; vault_init(&v, cfg.vault_path, cfg.store_plaintext);
        if (!strcmp(cmd, "--demo")) {
            char url[128];
            snprintf(url, sizeof(url), "http://127.0.0.1:%d/", cfg.port);
            HANDLE t = CreateThread(NULL, 0, open_browser, (LPVOID)lstrdup(url), 0, NULL);
            if (t) CloseHandle(t);
        }
        return web_server_run(&cfg, &v);
    }

    if (!strcmp(cmd, "--service")) {
        Vault v; vault_init(&v, cfg.vault_path, cfg.store_plaintext);
        return svc_run_as_service(&cfg, &v);
    }
    if (!strcmp(cmd, "--service-install")) return svc_install();
    if (!strcmp(cmd, "--service-uninstall")) return svc_uninstall();

    if (!strcmp(cmd, "--discover")) {
        char *json = net_discover(cfg.scan_timeout_ms, cfg.scan_max_hosts, cfg.trace_upstream);
        if (!json) { LOGE("discover 失败"); return E_INTERNAL; }
        printf("%s\n", json);
        free(json);
        return 0;
    }

    if (!strcmp(cmd, "--cred-ls") || !strcmp(cmd, "--cred-add") ||
        !strcmp(cmd, "--cred-del") || !strcmp(cmd, "--cred-get")) {
        Vault v;
        vault_init(&v, cfg.vault_path, cfg.store_plaintext);

        if (!strcmp(cmd, "--cred-ls")) {
            CredPlain list[64];
            int n = vault_list(&v, list, 64);
            if (n < 0) { LOGE("读取凭据失败 rc=%d", n); return n; }
            if (n == 0) { printf("（无已保存凭据）\n"); return 0; }
            for (int i = 0; i < n; i++) {
                CredPlain *c = &list[i];
                char f[32] = "";
                if (c->flags & CRED_FLAG_PLAINTEXT) snprintf(f, sizeof(f), " [明文]");
                printf("[%s] %-8s | %s | %s%s | %s\n",
                       c->id, cred_type_str(c->type), c->label, c->target, f, c->notes);
            }
            return 0;
        }

        if (!strcmp(cmd, "--cred-add")) {
            if (argc < 7) { fprintf(stderr, "用法: --cred-add <label> <type> <target> <username> <secret>\n"); return E_ARG; }
            CredPlain c; memset(&c, 0, sizeof(c));
            snprintf(c.label, sizeof(c.label), "%s", argv[2]);
            c.type = parse_type(argv[3]);
            snprintf(c.target, sizeof(c.target), "%s", argv[4]);
            snprintf(c.username, sizeof(c.username), "%s", argv[5]);
            snprintf(c.secret, sizeof(c.secret), "%s", argv[6]);
            int rc = vault_store(&v, &c);
            cred_zeroize(&c);
            if (rc != E_OK) { LOGE("保存失败 rc=%d", rc); return rc; }
            printf("已保存凭据（DPAPI 加密）\n");
            audit_log("cli", "cred-add", c.target, "executed", "label");
            return 0;
        }

        if (!strcmp(cmd, "--cred-del")) {
            if (argc < 3) { fprintf(stderr, "用法: --cred-del <id>\n"); return E_ARG; }
            int rc = vault_delete(&v, argv[2]);
            if (rc != E_OK) { LOGE("删除失败 rc=%d (%s)", rc, err_str(rc)); return rc; }
            printf("已删除 %s\n", argv[2]);
            return 0;
        }

        if (!strcmp(cmd, "--cred-get")) {
            if (argc < 3) { fprintf(stderr, "用法: --cred-get <id>\n"); return E_ARG; }
            CredPlain c; memset(&c, 0, sizeof(c));
            int rc = vault_get(&v, argv[2], &c);
            if (rc != E_OK) { LOGE("读取失败 rc=%d (%s)", rc, err_str(rc)); return rc; }
            printf("label=%s type=%s target=%s\nuser=%s\nsecret=%s\n",
                   c.label, cred_type_str(c.type), c.target, c.username, c.secret);
            cred_zeroize(&c);
            return 0;
        }
    }

    if (!strcmp(cmd, "--exec-local")) {
        if (argc < 3) { fprintf(stderr, "用法: --exec-local <命令>\n"); return E_ARG; }
        char out[8192];
        ExecOpts o = {false, 20};
        int rc = exec_local_run(argv[2], &o, out, sizeof(out));
        printf("%s", out);
        return rc;
    }

    if (!strcmp(cmd, "--exec-ssh") || !strcmp(cmd, "--exec-ssh-sudo")) {
        if (argc < 5) { fprintf(stderr, "用法: %s <ip> <cred-id> <命令>\n", cmd); return E_ARG; }
        Vault v; vault_init(&v, cfg.vault_path, cfg.store_plaintext);
        char out[8192];
        ExecOpts o = {!strcmp(cmd, "--exec-ssh-sudo"), 20};
        int rc = exec_remote_run(&v, argv[2], argv[3], argv[4], &o, out, sizeof(out));
        printf("%s", out);
        return rc;
    }

    if (!strcmp(cmd, "--agent")) {
        if (argc < 3) { fprintf(stderr, "用法: --agent <需求描述>\n"); return E_ARG; }
        Vault v; vault_init(&v, cfg.vault_path, cfg.store_plaintext);
        char out[32768];
        int rc = agent_run(&v, &cfg, argv[2], out, sizeof(out));
        printf("%s\n", out);
        return rc;
    }

    if (!strcmp(cmd, "--provider-ls") || !strcmp(cmd, "--provider-add") ||
        !strcmp(cmd, "--provider-use") || !strcmp(cmd, "--provider-del") ||
        !strcmp(cmd, "--apikey-set") || !strcmp(cmd, "--apikey-ls")) {

        if (!strcmp(cmd, "--apikey-ls")) {
            char names[64][64];
            int n = keystore_list(cfg.apikeys_path, names, 64);
            if (n <= 0) { printf("（无已保存的 API Key）\n"); return 0; }
            for (int i = 0; i < n; i++) printf("%s\n", names[i]);
            return 0;
        }
        if (!strcmp(cmd, "--apikey-set")) {
            if (argc < 4) { fprintf(stderr, "用法: --apikey-set <提供方名> <API_KEY>\n"); return E_ARG; }
            int rc = keystore_store(cfg.apikeys_path, argv[2], argv[3]);
            if (rc != E_OK) { LOGE("保存 API Key 失败 rc=%d", rc); return rc; }
            printf("已加密保存提供方「%s」的 API Key（独立存储 %s）\n", argv[2], cfg.apikeys_path);
            return 0;
        }

        ProviderList pl;
        provider_list_load(cfg.providers_path, &pl);

        if (!strcmp(cmd, "--provider-ls")) {
            if (pl.count == 0) { printf("（无提供方）\n"); return 0; }
            for (int i = 0; i < pl.count; i++) {
                AgentProvider *p = &pl.items[i];
                char keys[64][64]; int nk = keystore_list(cfg.apikeys_path, keys, 64);
                bool has = false;
                for (int k = 0; k < nk; k++) if (!strcmp(keys[k], p->name)) { has = true; break; }
                printf("[%s] %s  %s%s  model=%s  key=%s\n",
                       (pl.active[0] && !strcmp(pl.active, p->name)) ? "*" : " ",
                       p->name, p->base_url, p->endpoint, p->model, has ? "已设置" : "未设置");
            }
            return 0;
        }
        if (!strcmp(cmd, "--provider-add")) {
            if (argc < 6) { fprintf(stderr, "用法: --provider-add <名称> <base_url> <endpoint> <模型>\n"); return E_ARG; }
            AgentProvider *p = provider_find(&pl, argv[2]);
            if (!p) {
                if (pl.count >= AGENT_MAX_PROVIDERS) { fprintf(stderr, "提供方已满\n"); return E_INTERNAL; }
                p = &pl.items[pl.count++]; memset(p, 0, sizeof(*p));
            }
            snprintf(p->name, sizeof(p->name), "%s", argv[2]);
            snprintf(p->base_url, sizeof(p->base_url), "%s", argv[3]);
            snprintf(p->endpoint, sizeof(p->endpoint), "%s", argv[4]);
            snprintf(p->model, sizeof(p->model), "%s", argv[5]);
            if (!pl.active[0]) snprintf(pl.active, sizeof(pl.active), "%s", argv[2]);
            provider_list_save(cfg.providers_path, &pl);
            printf("已保存提供方「%s」\n", argv[2]);
            return 0;
        }
        if (!strcmp(cmd, "--provider-use")) {
            if (argc < 3 || !provider_find(&pl, argv[2])) { fprintf(stderr, "提供方不存在\n"); return E_NOTFOUND; }
            snprintf(pl.active, sizeof(pl.active), "%s", argv[2]);
            provider_list_save(cfg.providers_path, &pl);
            printf("已切换到「%s」\n", argv[2]);
            return 0;
        }
        if (!strcmp(cmd, "--provider-del")) {
            if (argc < 3) { fprintf(stderr, "用法: --provider-del <名称>\n"); return E_ARG; }
            int idx = -1;
            for (int i = 0; i < pl.count; i++) if (!strcmp(pl.items[i].name, argv[2])) { idx = i; break; }
            if (idx < 0) { fprintf(stderr, "提供方不存在\n"); return E_NOTFOUND; }
            for (int i = idx; i < pl.count - 1; i++) pl.items[i] = pl.items[i + 1];
            pl.count--;
            if (pl.active[0] && !strcmp(pl.active, argv[2])) { pl.active[0] = 0; if (pl.count) snprintf(pl.active, sizeof(pl.active), "%s", pl.items[0].name); }
            provider_list_save(cfg.providers_path, &pl);
            keystore_delete(cfg.apikeys_path, argv[2]);
            printf("已删除提供方「%s」\n", argv[2]);
            return 0;
        }
    }

    if (!strcmp(cmd, "--vendor-ls")) {
        for (int i = 0; i < vendors_count(); i++) {
            const VendorPreset *v = vendors_at(i);
            printf("%-12s %-24s %s%s\n", v->name, v->label, v->base_url, v->endpoint);
        }
        return 0;
    }

    if (!strcmp(cmd, "--provider-models")) {
        if (argc < 3) { fprintf(stderr, "用法: --provider-models <提供方名>\n"); return E_ARG; }
        const VendorPreset *vp = vendors_find(argv[2]);
        ProviderList pl;
        provider_list_load(cfg.providers_path, &pl);
        AgentProvider *p = provider_find(&pl, argv[2]);
        const char *base = p ? p->base_url : (vp ? vp->base_url : NULL);
        char models_url[600]; models_url[0] = 0;
        if (vp && vp->models_url[0]) snprintf(models_url, sizeof(models_url), "%s", vp->models_url);
        else if (base && base[0]) {
            size_t blen = strlen(base);
            snprintf(models_url, sizeof(models_url), "%s%smodels", base, (blen > 0 && base[blen - 1] == '/') ? "" : "/");
        } else { fprintf(stderr, "无法确定模型列表地址（先 --provider-add 或选择已知供应商）\n"); return E_ARG; }

        char key[512];
        if (keystore_get(cfg.apikeys_path, argv[2], key, sizeof(key)) != E_OK || !key[0]) {
            fprintf(stderr, "提供方「%s」尚未设置 API Key\n", argv[2]);
            return E_AUTH;
        }
        log_redact(key);
        printf("模型列表地址: %s\n", models_url);
        char *arr = vendor_models_fetch(models_url, key, cfg.agent.timeout_s);
        zeroize(key, sizeof(key));
        if (!arr) { fprintf(stderr, "获取模型失败（检查 Key / 地址 / 网络）\n"); return E_NET; }
        printf("%s\n", arr);
        free(arr);
        return 0;
    }

    if (!strcmp(cmd, "--tool-test")) {
        Vault v; vault_init(&v, cfg.vault_path, cfg.store_plaintext);
        ToolContext tc; tc.vault = &v; tc.cfg = &cfg;
        char out[16384];
        const ToolDef *td;

        td = tools_find("ping");
        cJSON *a = cJSON_CreateObject(); cJSON_AddStringToObject(a, "ip", "192.168.31.1");
        td->handler(a, &tc, out, sizeof(out)); cJSON_Delete(a);
        printf("ping => %s\n", out);

        td = tools_find("credential.list");
        td->handler(NULL, &tc, out, sizeof(out));
        printf("credential.list => %s\n", out);
        return 0;
    }

    if (!strcmp(cmd, "--risk-test")) {
        Confirmation c;
        if (risk_request(RISK_DESTRUCTIVE, "重启设备 192.168.1.1", "{\"cmd\":\"reboot\"}", 120, &c) != E_OK)
            return E_INTERNAL;
        printf("已创建确认请求: id=%s level=%s summary=%s\n", c.id, risk_level_str(c.level), c.summary);
        audit_log("cli", "risk-request", "192.168.1.1", "pending", "reboot");
        risk_decide(c.id, false);
        printf("已拒绝(denied)\n");
        audit_log("cli", "risk-decide", "192.168.1.1", "denied", "test");
        return 0;
    }

    fprintf(stderr, "命令 '%s' 尚未实现\n", cmd);
    return E_UNSUPPORTED;
}
