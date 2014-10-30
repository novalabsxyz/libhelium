/*
 * Copyright (C) 2014 Helium Systems Inc.
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

/* (Someday) cross-platform interface for logging. */

#ifndef HELIUM_LOGGING_H
#define HELIUM_LOGGING_H

#ifndef _WIN32
#include <syslog.h>
#endif

#ifdef _WIN32
#  ifdef helium_EXPORTS
#    define MODULE_API __declspec(dllexport)
#  else
#    define MODULE_API __declspec(dllimport)
#  endif
MODULE_API int _helium_logging_enabled; /* initialized to 0 by default */
#define helium_logging_start() _helium_logging_enabled = 1;
#define helium_log(priority, format, ...) if(_helium_logging_enabled) { printf(format, __VA_ARGS__); }
#define helium_dbg(format, ...) if(_helium_logging_enabled) { printf(format, __VA_ARGS__); }
#else
void helium_logging_start();
void helium_log(int level, const char *format, ...);
void helium_dbg(const char *format, ...);
#endif

#endif
