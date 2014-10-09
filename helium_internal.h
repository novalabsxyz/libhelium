// Copyright (c) 2014 Helium Systems, Inc.

#include <uv.h>

#include "helium.h"
#include "uthash.h"

/** 
 * test
 */
struct helium_connection_s {
  uv_loop_t *loop;
  // TODO use just one async_t here?
  uv_async_t send_async;
  uv_async_t subscribe_async;
  uv_async_t quit_async;
  uv_sem_t sem;
  uv_mutex_t mutex;
  uv_udp_t udp_handle;
  uv_timer_t subscription_timer;
  struct addrinfo connection_address;
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
