#ifndef LANMGR_WINCOMPAT_H
#define LANMGR_WINCOMPAT_H

/* Central Windows-includes shim. Include this FIRST in any .c that uses Win32 API.
 * Ensures winsock2.h precedes windows.h and fixes _WIN32_WINNT. */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

#endif
