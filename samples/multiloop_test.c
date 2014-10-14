#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <syslog.h>

#include <openssl/evp.h>
#include <openssl/bio.h>

#include "helium.h"

void test_callback(const helium_connection_t *conn, uint64_t sender_mac, char * const message, size_t count)
{
  syslog(LOG_USER, "1 Function-pointer callback got %s %zd\n", message, count);
  syslog(LOG_USER, "1 Mac address is %" PRIu64 "\n", sender_mac);
}

void test_callback2(const helium_connection_t *conn, uint64_t sender_mac, char * const message, size_t count)
{
  syslog(LOG_USER, "2 Function-pointer callback got %s %zd\n", message, count);
  syslog(LOG_USER, "2 Mac address is %" PRIu64 "\n", sender_mac);
}

int main(int argc, char *argv[])
{
  openlog("libhelium", LOG_PERROR | LOG_NDELAY | LOG_PID, LOG_USER);
  atexit(closelog);
  
  uv_loop_t my_loop;
  uv_loop_init(&my_loop);
  
  char *proxy = NULL;

  helium_connection_t *conn2 = helium_alloc(NULL);
  helium_open(conn2, proxy, test_callback2);
  
  helium_connection_t *conn = helium_alloc(&my_loop);
  helium_open(conn, proxy, test_callback);

  helium_token_t token;

  unsigned char *token1 = (unsigned char*)"c8GKvZyayaIhQpRjIo4aYQ==";
  unsigned char *token2 = (unsigned char*)"E3J1AVDORcwOFsQDajBWOQ==";

  helium_base64_token_decode(token1, strlen((char*)token1), token);
  helium_subscribe(conn, 18838586654721, token);
  helium_base64_token_decode(token2, strlen((char*)token2), token);
  helium_subscribe(conn2, 18838586654722, token);

  uv_run(&my_loop, UV_RUN_DEFAULT);
  
  helium_close(conn);
  helium_free(conn);
  return 0;
}
