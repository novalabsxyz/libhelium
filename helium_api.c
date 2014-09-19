#include <stdio.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "helium_api.h"

void _helium_buffer_alloc_callback(uv_handle_t *handle, size_t suggested, uv_buf_t *dst)
{
  char *chunk = malloc(suggested);
  memset(&chunk, 0, suggested);
  assert(chunk != 0);
  *dst = uv_buf_init(chunk, suggested);
}

void _helium_udp_recv_callback(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned int flags)
{
  uint64_t macaddr = 0; // TODO: extract this from the sockaddr with getnameinfo(3)
  
  assert(handle->data != NULL);
  helium_connection_t *conn = (helium_connection_t *)handle->data;

  conn->callback(conn, macaddr, buf->base, buf->len);
}

void _helium_send_callback(uv_udp_send_t *req, int status)
{
  
}

int helium_init(helium_connection_t *conn, char *proxy_addr)
{
  // should we parameterize this function so as to allow a passed loop?
  conn->loop = uv_default_loop();
  int err = uv_udp_init(conn->loop, &conn->udp_handle);

  if (err) {
    return err;
  }
  
  struct sockaddr_in v4addr;
  struct sockaddr_in6 v6addr;
  if (proxy_addr != NULL) {
      printf("binding ipv4\n");
    err = uv_ip4_addr("0.0.0.0", 0, &v4addr);
  }
  else {
      printf("binding ipv6\n");
    err = uv_ip6_addr("::", 0, &v6addr);
  }

  const struct sockaddr *addr = proxy_addr != NULL ? (struct sockaddr*)&v4addr : (struct sockaddr*)&v6addr;

  uv_udp_bind(&conn->udp_handle, addr, 0);

  if (err != 0) {
    return err;
  }
  
  conn->udp_handle.data = conn;
  conn->proxy_addr = proxy_addr;

  return 0;
}

int helium_send(helium_connection_t *conn, uint64_t macaddr, helium_token_t token, char *message, size_t count)
{
  char *target = NULL;
  struct addrinfo hints = {AF_UNSPEC, SOCK_DGRAM, 0, 0};
  if (conn->proxy_addr == NULL) {
      asprintf(&target, "%lX.d.helium.io", macaddr);
      printf("looking up %s\n", target);
      if (target == NULL) {
          return -1;
      }
      // only return ipv6 addresses
      hints.ai_family = AF_INET6;
  } else {
      printf("using ipv4 proxy\n");
      target = conn->proxy_addr;
      hints.ai_family=AF_INET;
  }

  struct addrinfo *address = NULL;
  int err = getaddrinfo(target, "2169", &hints, &address);

  if (err != 0) {
    return -1;
  }

  uv_buf_t buf = { message, count };
  uv_udp_send_t send_req;
  send_req.data = conn;
  err = uv_udp_send(&send_req, &conn->udp_handle, &buf, 1, address->ai_addr, _helium_send_callback);
  if (err != 0) {
      return -1;
  }
  
  return 0;
}

int helium_close(helium_connection_t *conn)
{
  uv_udp_recv_stop(&conn->udp_handle);

  return 0;
}

