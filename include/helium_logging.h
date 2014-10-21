/* Copyright (c) Helium Systems, 2014. */

/* (Someday) cross-platform interface for logging. */

#include <syslog.h>

void helium_logging_start();
void helium_log(int level, const char *format, ...) __attribute__((format(printf, 2, 3)));
void helium_dbg(const char *format, ...) __attribute__((format(printf, 1, 2)));
