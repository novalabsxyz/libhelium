
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/bio.h>

#include "helium.h"
#include "logging.h"

void test_callback(const helium_connection_t *conn, uint64_t sender_mac, char * const message, size_t count)
{
  printf("Function-pointer callback got %s %zd\n", message, count);
  printf("Mac address is %lu\n", sender_mac);
}


int base64_decode(unsigned char *input, int length, helium_token_t outbuf) {
  BIO *b64, *bmem, *decoder;

  b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  bmem = BIO_new_mem_buf(input, length);
  decoder = BIO_push(b64, bmem);
  BIO_flush(decoder);
  int readlen = BIO_read(decoder, outbuf, length);
  BIO_free_all(b64);
  return readlen;
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
  unsigned char token_in[32];
  char message[1024];
  int ret;
  while(1) {
    ret = scanf("%lx %s %[^\n]", &mac, token_in, message);
    if (ret > 0) {
      base64_decode(token_in, strlen((char*)token_in), token);
      printf("MAC %lu %s %s\n", mac, token_in, message);
      for (int i = 0; i < 16; i++) {
        printf("%u ", token[i]);
      }
      printf("\n");
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
