#include <stdio.h>
#include <string.h>
#ifdef _MSC_VER
#include "msvc_inttypes.h"
#else
#include <inttypes.h>
#endif

#include <openssl/evp.h>
#include <openssl/bio.h>

#include "helium.h"
#include "helium_logging.h"

void test_callback(const helium_connection_t *conn, uint64_t sender_mac, char * const message, size_t count)
{
  helium_dbg("Function-pointer callback got %s %zd\n", message, count);
  helium_dbg("Mac address is %" PRIu64 "\n", sender_mac);
}

int main(int argc, char *argv[])
{
  char *proxy = NULL;
  helium_connection_t *conn;
  uint64_t mac;
  helium_token_t token;
  unsigned char token_in[32];
  char message[1024];
  int ret;

  helium_logging_start();
  conn = helium_alloc();
  if (argc == 3 && strcmp("-p", argv[1]) == 0) {
    helium_dbg("proxy %s\n", argv[2]);
    proxy = argv[2];
  } else if (argc > 1) {
    printf("USAGE: %s -p <ipv4 proxy>\n", argv[0]);
    return 1;
  }

#if HAVE_BLOCKS
  helium_open_b(conn, proxy, ^(const helium_connection_t *conn, uint64_t mac, char *msg, size_t n) {
      helium_dbg("Block callback got %zu bytes from message %s\n", n, msg);
  });
#else
  helium_open(conn, proxy, test_callback);
#endif

  while(1) {
    ret = scanf("%" PRIx64 " %s %[^\n]", &mac, token_in, message);
    if (ret > 0) {
      helium_base64_token_decode(token_in, strlen((char*)token_in), token);
      if (strncmp("s", message, 1) == 0) {
        int  err = helium_subscribe(conn, mac, token);
        helium_dbg("subscribe result %d\n", err);
      } else if (strncmp("u", message, 1) == 0) {
        int  err = helium_unsubscribe(conn, mac);
        helium_dbg("unsubscribe result %d\n", err);
      } else {
        int  err = helium_send(conn, mac, token, (unsigned char*)message, strlen(message));
        helium_dbg("send result %d\n", err);
      }
    } else {
      /* invalid line, consume it */
      fgets(message, 1024, stdin);
      if (strncmp(message, "QUIT", 4) == 0) {
        printf("quitting\n");
        break;
      }
      printf("USAGE: <MAC> <Token> <Message>\n");
    }
  }

  helium_close(conn);
  helium_free(conn);

  return 0;
}
