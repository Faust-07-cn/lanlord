#ifndef LANMGR_SVC_H
#define LANMGR_SVC_H

#include "core/config.h"
#include "sec/vault.h"

/* Run the web server as a Windows service (blocks until stopped). */
int svc_run_as_service(Config *cfg, Vault *vault);

/* Register the "lanmgrd" service pointing at this exe (requires admin). */
int svc_install(void);

/* Delete the "lanmgrd" service (requires admin). */
int svc_uninstall(void);

#endif
