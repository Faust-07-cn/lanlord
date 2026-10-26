#include "wincompat.h"
#include "docker.h"
#include "exec/exec.h"
#include "core/error.h"
#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define DOCKER_CMD "docker ps --format '{{json .}}'"

static void docker_parse(char *out, cJSON *arr) {
    char *save = NULL;
    for (char *line = strtok_r(out, "\r\n", &save); line; line = strtok_r(NULL, "\r\n", &save)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p != '{') continue;
        cJSON *obj = cJSON_Parse(p);
        if (!obj) continue;
        cJSON *id = cJSON_GetObjectItemCaseSensitive(obj, "ID");
        cJSON *names = cJSON_GetObjectItemCaseSensitive(obj, "Names");
        cJSON *image = cJSON_GetObjectItemCaseSensitive(obj, "Image");
        cJSON *status = cJSON_GetObjectItemCaseSensitive(obj, "Status");
        cJSON *e = cJSON_CreateObject();
        cJSON_AddStringToObject(e, "id", cJSON_IsString(id) ? id->valuestring : "");
        cJSON_AddStringToObject(e, "names", cJSON_IsString(names) ? names->valuestring : "");
        cJSON_AddStringToObject(e, "image", cJSON_IsString(image) ? image->valuestring : "");
        cJSON_AddStringToObject(e, "status", cJSON_IsString(status) ? status->valuestring : "");
        cJSON_AddItemToArray(arr, e);
        cJSON_Delete(obj);
    }
}

static int finish(int rc, const char *err_raw, cJSON *arr, char *json_out, size_t outlen) {
    if (rc == E_OK) {
        char *s = cJSON_PrintUnformatted(arr);
        cJSON_Delete(arr);
        snprintf(json_out, outlen, "%s", s ? s : "[]");
        if (s) free(s);
        return rc;
    }
    cJSON_Delete(arr);
    snprintf(json_out, outlen, "%s", (err_raw && err_raw[0]) ? err_raw : "SSH 连接失败");
    return rc;
}

int docker_list_remote(Vault *v, const char *ip, const char *cred_id, char *json_out, size_t outlen) {
    if (outlen) json_out[0] = 0;
    char out[16384];
    ExecOpts o0 = { false, 20 };
    int rc = exec_remote_run(v, ip, cred_id, DOCKER_CMD, &o0, out, sizeof(out));
    if (rc != E_OK && strstr(out, "permission denied")) {
        /* user not in docker group -> retry with sudo -S */
        ExecOpts o1 = { true, 20 };
        rc = exec_remote_run(v, ip, cred_id, DOCKER_CMD, &o1, out, sizeof(out));
    }
    cJSON *arr = cJSON_CreateArray();
    if (rc == E_OK) docker_parse(out, arr);
    return finish(rc, out, arr, json_out, outlen);
}

int docker_list_remote_direct(const char *ip, const char *username, const char *password,
                              char *json_out, size_t outlen) {
    if (outlen) json_out[0] = 0;
    char out[16384];
    ExecOpts o0 = { false, 20 };
    int rc = exec_remote_run_direct(ip, username, password, DOCKER_CMD, &o0, out, sizeof(out));
    if (rc != E_OK && strstr(out, "permission denied")) {
        ExecOpts o1 = { true, 20 };
        rc = exec_remote_run_direct(ip, username, password, DOCKER_CMD, &o1, out, sizeof(out));
    }
    cJSON *arr = cJSON_CreateArray();
    if (rc == E_OK) docker_parse(out, arr);
    return finish(rc, out, arr, json_out, outlen);
}
