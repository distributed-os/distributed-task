#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

#include "log.h"

#ifdef DEBUG
int loglevel = LOGLEVEL_DEBUG;
#else
int loglevel = LOGLEVEL_WARNING;
#endif

void set_loglevel(int level)
{
    if (level > 0 && level < LOGLEVEL_MAX) {
        loglevel = level;
    }
}

int get_loglevel()
{
    return loglevel;
}

void log_init(int level)
{
    set_loglevel(level);
}

static void report(const char *prefix, const char *err, va_list params)
{
    char msg[1024];
    vsnprintf(msg, sizeof(msg), err, params);
    fprintf(stderr, "%s%s\n", prefix, msg);
}

static void debug_builtin(const char *debug, va_list params)
{
    report("[Debug] ", debug, params);
}

static void info_builtin(const char *info, va_list params)
{
    report("[Info] ", info, params);
}

static void warn_builtin(const char *warn, va_list params)
{
    report("[Warning] ", warn, params);
}

static void error_builtin(const char *err, va_list params)
{
    report("[Error] ", err, params);
}

static void die_builtin(const char *err, va_list params)
{
    report("[Fatal] ", err, params);
    exit(128);
}

void __pr_debug(const char *debug, ...)
{
    va_list params;

    if (loglevel < LOGLEVEL_DEBUG)
        return;

    va_start(params, debug);
    debug_builtin(debug, params);
    va_end(params);
}

void pr_info(const char *info, ...)
{
    va_list params;

    if (loglevel < LOGLEVEL_INFO)
        return;

    va_start(params, info);
    info_builtin(info, params);
    va_end(params);
}

void pr_warning(const char *warn, ...)
{
    va_list params;

    if (loglevel < LOGLEVEL_WARNING)
        return;

    va_start(params, warn);
    warn_builtin(warn, params);
    va_end(params);
}

void pr_err(const char *err, ...)
{
    va_list params;

    if (loglevel < LOGLEVEL_ERROR)
        return;

    va_start(params, err);
    error_builtin(err, params);
    va_end(params);
}

void die(const char *err, ...)
{
    va_list params;

    va_start(params, err);
    die_builtin(err, params);
    va_end(params);
}
