/*
 * Copyright (C) 2014 Helium Systems Inc.
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#include <stdlib.h>
#ifdef _WIN32
#include <stdio.h>
//int _helium_logging_enabled = 0;
#else
#include <syslog.h>
#endif
#include <stdarg.h>


#include "helium_logging.h"

#ifndef _WIN32
void helium_logging_start()
{

  openlog("libhelium", LOG_PERROR | LOG_NDELAY | LOG_PID, LOG_USER);
  atexit(closelog);
}
#endif

#ifndef _WIN32
void helium_log(int priority, const char *format, ...)
{
  va_list args;
  va_start(args, format);
  vsyslog(priority, format, args);
}
#endif

#ifndef _WIN32
void helium_dbg(const char *format, ...)
{
  va_list args;
  va_start(args, format);
  vsyslog(LOG_DEBUG, format, args);
}
#endif
