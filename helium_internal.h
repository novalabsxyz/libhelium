// Copyright (c) 2014 Helium Systems, Inc.

#include <uv.h>

#include "helium.h"
#include "uthash.h"

struct helium_connection_s {
  uv_loop_t *loop;
  uv_thread_t thread;
  uv_async_t async;
  uv_udp_t udp_handle;
  struct addrinfo connection_address;
  char *proxy_addr;
  helium_callback_t callback;
  struct helium_mac_token_map *token_map;
#if HAVE_BLOCKS
  helium_block_t callback_block;
#endif
};

struct helium_mac_token_map {
  uint64_t mac;
  helium_token_t token;
  UT_hash_handle hh;
};
