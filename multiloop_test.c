
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/bio.h>

#include "helium.h"
#include "logging.h"

void test_callback(const helium_connection_t *conn, uint64_t sender_mac, char * const message, size_t count)
{
  helium_dbg("1 Function-pointer callback got %s %zd\n", message, count);
  helium_dbg("1 Mac address is %lu\n", sender_mac);
}

void test_callback2(const helium_connection_t *conn, uint64_t sender_mac, char * const message, size_t count)
{
  helium_dbg("2 Function-pointer callback got %s %zd\n", message, count);
  helium_dbg("2 Mac address is %lu\n", sender_mac);
}


int main(int argc, char *argv[])
{
  helium_logging_start();
  char *proxy = NULL;
  helium_connection_t *conn = helium_alloc();
  helium_open(conn, proxy, test_callback);

  helium_connection_t *conn2 = helium_alloc();
  helium_open(conn2, proxy, test_callback2);

  helium_token_t token;

  unsigned char *token1 = (unsigned char*)"c8GKvZyayaIhQpRjIo4aYQ==";
  unsigned char *token2 = (unsigned char*)"E3J1AVDORcwOFsQDajBWOQ==";

  helium_base64_token_decode(token1, strlen((char*)token1), token);
  helium_subscribe(conn, 18838586654721, token);
  helium_base64_token_decode(token2, strlen((char*)token2), token);
  helium_subscribe(conn2, 18838586654722, token);

  while(1) {
  }

  helium_close(conn);
  helium_free(conn);
  return 0;
}
