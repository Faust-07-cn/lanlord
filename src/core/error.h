#ifndef LANMGR_ERROR_H
#define LANMGR_ERROR_H

/* Common error codes returned across modules. */
enum {
    E_OK = 0,
    E_ARG = 1,
    E_NOMEM = 2,
    E_IO = 3,
    E_NOTFOUND = 4,
    E_AUTH = 5,
    E_DENIED = 6,
    E_TIMEOUT = 7,
    E_NET = 8,
    E_UNSUPPORTED = 9,
    E_INTERNAL = 10,
};

/* Human-readable description of an error code. */
const char *err_str(int code);

#endif
