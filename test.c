
#include <stdio.h>
#include <string.h>

#include "helium.h"
#include "logging.h"

void test_callback(const helium_connection_t *conn, uint64_t sender_mac, char * const message, size_t count)
{
  printf("Function-pointer callback got %s %zd\n", message, count);
  printf("Mac address is %luX", sender_mac);
}

int main(int argc, char *argv[])
{
  helium_logging_start();
  char *proxy = NULL;
  //helium_token_t token = "abcdefghijklmnop";
  helium_connection_t conn;
  if (argc == 3 && strcmp("-p", argv[1]) == 0) {
    printf("proxy %s\n", argv[2]);
    proxy = argv[2];
  } else if (argc > 1) {
    printf("USAGE: %s -p <ipv4 proxy>\n", argv[0]);
    return 1;
  }

#if HAVE_BLOCKS
  helium_init_b(&conn, proxy, ^(const helium_connection_t *conn, uint64_t mac, char *msg, size_t n) {
      helium_dbg("Block callback got %zu bytes from message %s", n, msg);
  });
#else
  helium_init(&conn, proxy, test_callback);
#endif

  uint64_t mac;
  helium_token_t token;
  char message[1024];
  int ret;
  while(1) {
    ret = scanf("%lx %16c %[^\n]", &mac, token, message);
    if (ret > 0) {
      printf("MAC %lu %s %s\n", mac, token, message);
      int  err = helium_send(&conn, mac, token, (unsigned char*)message, strlen(message));
      helium_dbg("send result %d\n", err);
    } else {
      // invalid line, consume it
      fgets(message, 1024, stdin);
      printf("USAGE: <MAC> <Token> <Message>\n");
    }
  }
  return 0;
}
