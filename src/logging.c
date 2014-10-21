/* logging.c */

#include <stdlib.h>
#ifndef _WIN32
#include <syslog.h>
#endif
#include <stdarg.h>

void helium_logging_start()
{
#ifndef _WIN32
  openlog("libhelium", LOG_PERROR | LOG_NDELAY | LOG_PID, LOG_USER);
  atexit(closelog);
#endif
}

void helium_log(int priority, const char *format, ...)
{
#ifndef _WIN32
  va_list args;
  va_start(args, format);
  vsyslog(priority, format, args);
#endif
}

void helium_dbg(const char *format, ...)
{
#ifndef _WIN32
  va_list args;
  va_start(args, format);
  vsyslog(LOG_DEBUG, format, args);
#endif
}
