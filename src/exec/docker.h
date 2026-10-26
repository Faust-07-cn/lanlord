#ifndef LANMGR_DOCKER_H
#define LANMGR_DOCKER_H

#include "sec/vault.h"
#include <stddef.h>

/* List a remote device's Docker containers via SSH (docker ps --format '{{json .}}').
 * Fills json_out with a JSON array of {id,names,image,status}. Returns E_OK on success,
 * or the SSH/exec error code. */
int docker_list_remote(Vault *v, const char *ip, const char *cred_id, char *json_out, size_t outlen);

/* List Docker containers using an inline username/password (not persisted). */
int docker_list_remote_direct(const char *ip, const char *username, const char *password,
                              char *json_out, size_t outlen);

#endif
