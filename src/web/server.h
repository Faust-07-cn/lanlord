#ifndef LANMGR_WEB_SERVER_H
#define LANMGR_WEB_SERVER_H

#include "core/config.h"
#include "sec/vault.h"

/* Serve the demo web UI + JSON API on 127.0.0.1:cfg->port until stopped.
 * cfg is mutable so /api/auth can update + persist the authorization mode. */
int web_server_run(Config *cfg, Vault *vault);

#endif
