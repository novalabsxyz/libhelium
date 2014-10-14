// Copyright (c) 2014 Helium Systems, Inc.

#include <uv.h>

#include "helium.h"
#include "uthash.h"

struct helium_connection_s {
  uv_loop_t *loop;
  uv_async_t async_handle;

  uv_sem_t sem;
  uv_mutex_t mutex;
  
  uv_udp_t udp_handle;
  uv_timer_t subscription_timer;
  char *proxy_addr;
  helium_callback_t callback;
  void *context;
  struct helium_mac_token_map *token_map;
  struct helium_mac_token_map *subscription_map;
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

struct helium_mac_token_map {
  uint64_t mac;
  helium_token_t token;
  UT_hash_handle hh;
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
  
  // NULL if a subscribe, unsubscribe, or quit request
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
