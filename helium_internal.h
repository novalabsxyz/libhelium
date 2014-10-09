// Copyright (c) 2014 Helium Systems, Inc.

#include <uv.h>

#include "helium.h"
#include "uthash.h"

struct helium_connection_s {
  uv_loop_t *loop;
  uv_async_t async_handle;
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

struct helium_mac_token_map {
  uint64_t mac;
  helium_token_t token;
  UT_hash_handle hh;
};

typedef enum {
  SEND_REQUEST = 0,
  SUBSCRIBE_REQUEST,
  QUIT_REQUEST
} helium_request_type_t;

struct helium_request_s {
  helium_request_type_t request_type;
  helium_connection_t *conn;
  uint64_t macaddr;
  helium_token_t token;
  union {
    struct {
      unsigned char *message;
      size_t count;
    } send_request;

    struct {
      unsigned char subscribe; // currently unused, but we'll use this for unsubscribe
    } subscribe_request;
  } as;
};

int _handle_send_request(helium_connection_t *conn,
                         uint64_t macaddr,
                         helium_token_t token,
                         unsigned char *message,
                         size_t count);

int _handle_subscribe_request(helium_connection_t *conn,
                              uint64_t macaddr,
                              helium_token_t token,
                              unsigned char subscribe);

int _handle_quit(helium_connection_t *conn);
