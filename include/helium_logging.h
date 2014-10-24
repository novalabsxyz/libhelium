/* Copyright (c) Helium Systems, 2014. */

/* (Someday) cross-platform interface for logging. */

#ifndef _WIN32
#include <syslog.h>
#endif

#ifdef _WIN32
#  ifdef helium_EXPORTS
#    define MODULE_API __declspec(dllexport)
#  else
#    define MODULE_API __declspec(dllimport)
#  endif
#else
#  define MODULE_API
#endif

MODULE_API void helium_logging_start();
MODULE_API void helium_log(int level, const char *format, ...);
MODULE_API void helium_dbg(const char *format, ...);
