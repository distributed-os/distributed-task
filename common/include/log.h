#ifndef __LOG_H__
#define __LOG_H__

#define LOGLEVEL_ERROR      0
#define LOGLEVEL_WARNING    1
#define LOGLEVEL_INFO       2
#define LOGLEVEL_DEBUG      3
#define LOGLEVEL_MAX        4

void set_loglevel(int level);
int get_loglevel();
void log_init(int level);

void pr_err(const char *err, ...);
void pr_warning(const char *err, ...);
void pr_info(const char *err, ...);
void __pr_debug(const char *debug, ...);
#define pr_debug(fmt, ...)                      \
    do {                                \
        __pr_debug("(%s) %s:%d: " fmt, __FILE__,    \
            __func__, __LINE__, ##__VA_ARGS__); \
    } while (0)

#endif
