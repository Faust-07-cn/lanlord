#ifndef LANMGR_LOG_H
#define LANMGR_LOG_H

typedef enum { LOG_TRACE = 0, LOG_DEBUG = 1, LOG_INFO = 2, LOG_WARN = 3, LOG_ERROR = 4 } LogLevel;

void log_init(const char *path, LogLevel level);
void log_set_level(LogLevel level);
/* Register a sensitive string; all future log lines redact it (overwrites with '*'s). */
void log_redact(const char *secret);
void log_close(void);

void log_msg(LogLevel lvl, const char *fmt, ...);

#define LOGT(...) log_msg(LOG_TRACE, __VA_ARGS__)
#define LOGD(...) log_msg(LOG_DEBUG, __VA_ARGS__)
#define LOGI(...) log_msg(LOG_INFO,  __VA_ARGS__)
#define LOGW(...) log_msg(LOG_WARN,  __VA_ARGS__)
#define LOGE(...) log_msg(LOG_ERROR, __VA_ARGS__)

#endif
