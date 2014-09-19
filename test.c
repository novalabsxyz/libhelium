
#include <stdio.h>
#include <string.h>

#include "helium_api.h"

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

    helium_init(&conn, proxy);

    int  err = helium_send(&conn, 0xdeadbeef, token, "hello", 5);

    printf("send result %d\n", err);

    return 0;
}
