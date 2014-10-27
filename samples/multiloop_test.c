/*
 * Copyright (C) 2014 Helium Systems Inc.
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include <openssl/evp.h>
#include <openssl/bio.h>

#include "helium.h"
#include "helium_logging.h"

void test_callback(const helium_connection_t *conn, uint64_t sender_mac, char * const message, size_t count)
{
  helium_dbg("1 Function-pointer callback got %s %zd\n", message, count);
  helium_dbg("1 Mac address is %" PRIu64 "\n", sender_mac);
}

void test_callback2(const helium_connection_t *conn, uint64_t sender_mac, char * const message, size_t count)
{
  helium_dbg("2 Function-pointer callback got %s %zd\n", message, count);
  helium_dbg("2 Mac address is %" PRIu64 "\n", sender_mac);
}

int main(int argc, char *argv[])
{
  char *proxy = NULL;
  helium_connection_t *conn, *conn2;
  helium_token_t token;
  unsigned char *token1, *token2;
  char message[1024];

  helium_logging_start();

  conn2 = helium_alloc();
  helium_open(conn2, proxy, test_callback2);

  conn = helium_alloc();
  helium_open(conn, proxy, test_callback);

  token1 = (unsigned char*)"vvseLv3rAtsVl2BdnW4S5A==";
  token2 = (unsigned char*)"WMjvdsPlReLHHAJqnbqvPw==";

  helium_base64_token_decode(token1, strlen((char*)token1), token);
  helium_subscribe(conn, 18838586654721, token);
  helium_base64_token_decode(token2, strlen((char*)token2), token);
  helium_subscribe(conn2, 18838586654722, token);
  while(1) {
    fgets(message, 1024, stdin);
    if (strncmp(message, "QUIT", 4) == 0) {
      printf("quitting\n");
      break;
    }
  }

  helium_close(conn);
  helium_free(conn);

  helium_close(conn2);
  helium_free(conn2);

  return 0;
}
