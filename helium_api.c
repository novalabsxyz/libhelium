#include <stdio.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "helium_api.h"

struct helium_connection_s {
  uv_loop_t *loop;
  uv_udp_t udp_recv_handle;
  uv_udp_t udp_send_handle;
  struct addrinfo connection_address;
  // should this be a hashtable of mac addresses => callbacks? probably
  helium_callback_t callback;
};

void _helium_buffer_alloc_callback(uv_handle_t *handle, size_t suggested, uv_buf_t *dst)
{
  char *chunk = malloc(suggested);
  memset(&chunk, 0, suggested);
  assert(chunk != 0);
  *dst = uv_buf_init(chunk, suggested);
}

void _helium_udp_recv_callback(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr addr, unsigned)
{
  uint64_t macaddr = 0; // TODO: extract this from the sockaddr with getnameinfo(3)
  
  assert(handle->data != NULL);
  helium_connection_t *conn = (helium_connection_t *)handle->data;

  conn->callback(conn, macaddr, buf->base, buf->len);
}

void _helium_connect_getaddrinfo_callback(uv_getaddrinfo_t *req, int status, struct addrinfo *res)
{
  // what to do here?
  assert(req->data != NULL);
  helium_connection_t * const conn = (helium_connection_t *)req->data;

  if (res != NULL) {
    memcpy((char *)&conn->connection_address, (const char *)res, sizeof(struct addrinfo));

    // TODO: specify ipv6 here
    uv_udp_bind(&conn->udp_send_handle, (const struct sockaddr*)&conn->connection_address, 0);

    // XXX: this is not right, I'm not binding to the right address
    uv_udp_bind(&conn->udp_recv_handle, (const struct sockaddr*)&conn->connection_address, 0);

    uv_udp_recv_start(&conn->udp_recv_handle, _helium_buffer_alloc_callback, _helium_udp_recv_callback);
  }
  
}

void _helium_send_callback(uv_udp_send_t *req, int status)
{
  
}

int helium_init(helium_connection_t *conn, const char *ipv4_proxy_address)
{
  if (ipv4_proxy_address != NULL) {
    // set the ipv4 proxy here
  }

  conn->loop = uv_default_loop();
  uv_udp_init(conn->loop, &conn->udp_recv_handle);
  uv_udp_init(conn->loop, &conn->udp_send_handle);
  conn->udp_recv_handle.data = conn;
  conn->udp_send_handle.data = conn;

  return 0;
}

int helium_connect(helium_connection_t *conn, uint64_t macaddr, helium_callback_t callback)
{
  char *domain = NULL;

  asprintf(&domain, "%lX.d.helium.co", macaddr);

  conn->callback = callback;

  if (domain == NULL) {
    fprintf(stderr, "libhelium: out of memory");
    abort();
  }

  uv_getaddrinfo_t addr_req;
  addr_req.data = conn;

  // I feel like we should invoke this synchronously
  uv_getaddrinfo(conn->loop, &addr_req, _helium_connect_getaddrinfo_callback, domain, NULL, NULL);
  // or perhaps lock here?
  
  return 0;
}

int helium_send(helium_connection_t *conn, uint64_t macaddr, helium_token_t token, char *message, size_t count)
{
  // TODO
  uv_buf_t buf = { message, count };
  uv_udp_send_t send_request;
  send_request.data = conn;
  uv_udp_send(&send_request, &conn->udp_send_handle, &buf, 1, &conn->connection_address, _helium_send_callback);

  return 0;
}

int helium_close(helium_connection_t *conn)
{
  uv_udp_recv_stop(&conn->udp_recv_handle);

  return 0;
}

