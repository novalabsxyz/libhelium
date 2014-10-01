
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

void _run_my_loop(void *arg)
{
  uv_loop_t *loop = (uv_loop_t *)arg;
  uv_run(loop, UV_RUN_DEFAULT);
}

int main(int argc, char *argv[])
{
  uv_thread_t my_thread_runner;
  uv_loop_t *my_loop = uv_loop_new();
  uv_loop_init(my_loop);
  uv_thread_create(&my_thread_runner, _run_my_loop, (void *)my_loop);
  
  
  helium_logging_start();
  char *proxy = NULL;
  helium_connection_t *conn = helium_alloc(NULL);
  helium_open(conn, proxy, test_callback);

  helium_connection_t *conn2 = helium_alloc(my_loop);
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

  uv_thread_join(&my_thread_runner);
  helium_close(conn);
  helium_free(conn);
  return 0;
}
