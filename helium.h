/**
   @file helium.h
   @authors the Helium team
   @copyright Helium Systems, 2014
*/

#include <stdio.h>
#include <stdint.h>
#include <uv.h>

#ifndef HELIUM_API_H
#define HELIUM_API_H

const char *libhelium_version();

void helium_logging_start(); // debug

// I think char[16] is preferable to char* here because there
// may be embedded NULs therein, and people think of char* as
// NUL-terminated.
typedef unsigned char helium_token_t[16];

typedef struct helium_connection_s helium_connection_t;

#if HAVE_BLOCKS
typedef void (^helium_block_t)(const helium_connection_t *conn, uint64_t sender_mac, char * const message, size_t count);
#endif

typedef void (*helium_callback_t)(const helium_connection_t *conn, uint64_t sender_mac, char * const message, size_t count);

helium_connection_t *helium_alloc(void) __attribute__((malloc));
void helium_free(helium_connection_t *conn);

/**
   @brief Open a helium connection, receiving data with the provided callback.

   A `helium_open` operation must be balanced by a call to `helium_close()`.

   @param conn The connection to open.
   @param proxy_addr An optional IPv4 proxy to use. If `NULL`, IPv6 is used.
   @param callback A function pointer that will be invoked when this connection receives data.
*/

int helium_open(helium_connection_t *conn, char *proxy_addr, helium_callback_t callback);
int helium_close(helium_connection_t *conn);

#if HAVE_BLOCKS
int helium_open_b(helium_connection_t *conn, char *proxy_addr, helium_block_t callback);
#endif

int helium_subscribe(helium_connection_t *conn, uint64_t macaddr, helium_token_t token);
int helium_send(helium_connection_t *conn, uint64_t macaddr, helium_token_t token, unsigned char *message, size_t count);

void *helium_get_context(const helium_connection_t *conn);
void helium_set_context(helium_connection_t *conn, void *context);

// convenience method for base64 decoding
int helium_base64_token_decode(const unsigned char *input, int length, helium_token_t outbuf);


#endif /* HELIUM_API_H */
