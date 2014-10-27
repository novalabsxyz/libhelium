/*
 * Copyright (C) 2014 Helium Systems Inc.
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

/* (Someday) cross-platform interface for logging. */

#ifndef _WIN32
#include <syslog.h>
#endif

void helium_logging_start();
void helium_log(int level, const char *format, ...);
void helium_dbg(const char *format, ...);
