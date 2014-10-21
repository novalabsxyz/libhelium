/* Copyright (c) 2014 Helium Systems, Inc. */

#include <uv.h>

#include "helium.h"
#include "hashmap.h"

struct helium_connection_s {
  uv_loop_t *loop;
  uv_thread_t *thread;

  uv_async_t async_handle;
  uv_sem_t sem;
  uv_mutex_t mutex;

  uv_udp_t udp_handle;
  uv_timer_t subscription_timer;
  char *proxy_addr;
  helium_callback_t callback;
  void *context;
  hashmap token_map;
  hashmap subscription_map;
#if HAVE_BLOCKS
  helium_block_t callback_block;
#endif
};

struct helium_callback_invocation_s {
  struct helium_connection_s *conn;
  char *message;
  uint64_t mac;
  int res;
};

typedef enum {
  SEND_REQUEST = 0,
  SUBSCRIBE_REQUEST,
  UNSUBSCRIBE_REQUEST,
  QUIT_REQUEST
} helium_request_type_t;

struct helium_request_s {
  helium_request_type_t request_type;
  helium_connection_t *conn;
  uint64_t macaddr;
  helium_token_t token;
  
  /* NULL if a subscribe, unsubscribe, or quit request */
  unsigned char *message;
  size_t count;
};

int _handle_send_request(helium_connection_t *conn,
                         uint64_t macaddr,
                         helium_token_t token,
                         unsigned char *message,
                         size_t count);

int _handle_subscribe_request(helium_connection_t *conn,
                              uint64_t macaddr,
                              helium_token_t token);

int _handle_quit(helium_connection_t *conn);
