/* Copyright (c) Helium Systems, 2014. */

/* (Someday) cross-platform interface for logging. */

#ifndef _WIN32
#include <syslog.h>
#endif

void helium_logging_start();
void helium_log(int level, const char *format, ...);
void helium_dbg(const char *format, ...);
