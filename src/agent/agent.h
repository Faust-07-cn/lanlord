#ifndef LANMGR_AGENT_H
#define LANMGR_AGENT_H

#include "sec/vault.h"
#include "core/config.h"
#include <stddef.h>

/* Run the tool-calling agent for a natural-language requirement.
 * Returns E_OK and final answer text in out, or an error code. */
int agent_run(Vault *v, const Config *cfg, const char *requirement, char *out, size_t outlen);

#endif
