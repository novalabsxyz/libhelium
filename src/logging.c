/* logging.c */

#include <stdlib.h>
#ifdef _WIN32
#include <stdio.h>
#else
#include <syslog.h>
#endif
#include <stdarg.h>

#include "helium_logging.h"

void helium_logging_start()
{
#ifndef _WIN32
  openlog("libhelium", LOG_PERROR | LOG_NDELAY | LOG_PID, LOG_USER);
  atexit(closelog);
#endif
}

void helium_log(int priority, const char *format, ...)
{
  va_list args;
  va_start(args, format);
#ifdef _WIN32
  printf(format, args);
#else
  vsyslog(priority, format, args);
#endif
}

void helium_dbg(const char *format, ...)
{
  va_list args;
  va_start(args, format);
#ifdef _WIN32
  printf(format, args);
#else
  vsyslog(LOG_DEBUG, format, args);
#endif
}
