// Copyright (c) 2014 Helium Systems, Inc.

#include <stdio.h>
#include <stdint.h>
#include <uv.h>

#ifndef HELIUM_API_H
#define HELIUM_API_H

const char *libhelium_version();

// I think char[16] is preferable to char* here because there
// may be embedded NULs therein, and people think of char* as
// NUL-terminated.
typedef unsigned char helium_token_t[16];

struct helium_connection_s;
struct helium_mac_token_map;

typedef struct helium_connection_s helium_connection_t;

// Would like a block-based API but for now let's just do function pointers.
#if HAVE_BLOCKS
typedef void (^helium_block_t)(const helium_connection_t *conn, uint64_t sender_mac, char * const message, size_t count);
#endif

typedef void (*helium_callback_t)(const helium_connection_t *conn, uint64_t sender_mac, char * const message, size_t count);

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

int helium_init(helium_connection_t *conn, char *proxy_addr, helium_callback_t callback);

#if HAVE_BLOCKS
int helium_init_b(helium_connection_t *conn, char *proxy_addr, helium_block_t callback);
#endif

int helium_close(helium_connection_t *conn);
int helium_send(helium_connection_t *conn, uint64_t macaddr, helium_token_t token, unsigned char *message, size_t count);

#endif /* HELIUM_API_H */
