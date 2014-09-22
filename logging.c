// logging.c

#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>

void helium_logging_start()
{
  openlog("libhelium", LOG_PERROR | LOG_NDELAY | LOG_PID, LOG_USER);
  atexit(closelog);
}

void helium_log(int priority, const char *format, ...)
{
  va_list args;
  va_start(args, format);
  vsyslog(priority, format, args);
}

void helium_dbg(const char *format, ...)
{
  va_list args;
  va_start(args, format);
  vsyslog(LOG_DEBUG, format, args);
}
