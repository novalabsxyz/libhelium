
#include <stdio.h>
#include <string.h>

#include "helium_api.h"

void test_callback(const helium_connection_t *conn, uint64_t sender_mac, char * const message, size_t count) {
  printf("callback got %s %zd\n", message+1, count);
}

int main(int argc, char *argv[]) {

  char *proxy = NULL;
  helium_token_t token = "abcdefghijklmnop";
  helium_connection_t conn;
  printf("argc %d\n", argc);
  if (argc == 3 && strcmp("-p", argv[1]) == 0) {
    printf("proxy %s\n", argv[2]);
    proxy = argv[2];
  } else if (argc > 1) {
    printf("USAGE: %s -p <ipv4 proxy>\n", argv[0]);
    return 1;
  }

  // helium_init(&conn, proxy, test_callback);

  helium_init_b(&conn, proxy, ^(const helium_connection_t *conn, uint64_t mac, char *msg, size_t n) {
      
  });

  printf("blargh\n");

  char line[256];
  while(1) {
    char *p = fgets (line, 256, stdin);
    if (p != NULL) {
      size_t last = strlen(line) - 1;
      if (line[last] == '\n') {
        line[last] = '\0';
      }

      int  err = helium_send(&conn, 0xdeadbeef, token, line, strlen(line));
      printf("send result %d\n", err);
    }
  }
  return 0;
}
