#include <stdio.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "helium_api.h"

struct helium_send_req_s {
  uint64_t macaddr;
  helium_token_t token;
  char *message;
  size_t count;
  helium_connection_t *conn;
};

void _helium_buffer_alloc_callback(uv_handle_t *handle, size_t suggested, uv_buf_t *dst)
{
  printf("in allocate, allocating %zd bytes\n", suggested);
  char *chunk = malloc(suggested);
  assert(chunk != NULL);
  memset(chunk, 0, suggested);
  *dst = uv_buf_init(chunk, suggested);
}

void _helium_udp_recv_callback(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned int flags)
{
  if (nread == 0) {
    return;
  }
  uint64_t macaddr = 0;
  const size_t BUFLEN = 256;

  char host[BUFLEN];
  char serv[BUFLEN];

  assert(handle->data != NULL);
  helium_connection_t *conn = (helium_connection_t *)handle->data;

  // Assumption: NULL proxy address means we're in IPv6 mode.
  // Used to have the larger of the two sizes here; that could be safer.
  const size_t enough
    = conn->proxy_addr == NULL
    ? sizeof(struct sockaddr_in6)
    : sizeof(struct sockaddr);

  int err = getnameinfo(addr, enough, host, BUFLEN, serv, BUFLEN, 0);


  if (err != 0) {
    const char *err = gai_strerror(errno);
    fprintf(stderr, "Error in Helium callback: getnameinfo failed, reason: %s\n", err);
    return;
  }

  if (strncmp(host, "localhost", BUFSIZ) == 0) {
    // testing
    fprintf(stderr, "from localhost, just testing\n");
    strcpy(host, "deadbeef.d.helium.co");
  }

  printf("Received host is %s\n", host);

  unsigned int whatever = 0;
  err = sscanf(host, "%x.d.helium.co", &whatever);
  macaddr = whatever;
  
  if (err == 0) {
    fprintf(stderr, "Couldn't extract mac address from host %s\n", host);
  } else {
    fprintf(stdout, "Extracted MAC is %lX\n", macaddr);
  }
  conn->callback(conn, macaddr, buf->base, nread);
}

void _helium_send_callback(uv_udp_send_t *req, int status)
{

  printf("sent %d\n", status);
  if (status == 0) {
    free(req);
  }
}

void _helium_do_udp_send(uv_async_t *handle) {

  struct helium_send_req_s *req = (struct helium_send_req_s*)handle->data;
  helium_connection_t *conn = req->conn;
  char *target = NULL;
  struct addrinfo hints = {AF_UNSPEC, SOCK_DGRAM, 0, 0};
  if (conn->proxy_addr == NULL) {
    asprintf(&target, "%lX.d.helium.io", req->macaddr);
    printf("looking up %s\n", target);
    if (target == NULL) {
      return;
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
    return;
  }

  uv_buf_t buf = { req->message, req->count };
  uv_udp_send_t *send_req = malloc(sizeof(uv_udp_send_t));
  send_req->data = conn;
  err = uv_udp_send(send_req, &conn->udp_handle, &buf, 1, address->ai_addr, _helium_send_callback);
}

void _bootup(void *arg) {
  helium_connection_t *conn = (helium_connection_t *)arg;
  uv_run(conn->loop, UV_RUN_DEFAULT);
}

int helium_init(helium_connection_t *conn, char *proxy_addr, helium_callback_t callback)
{
  // should we parameterize this function so as to allow a passed loop?
  conn->loop = uv_default_loop();
  uv_async_init(conn->loop, &conn->async, _helium_do_udp_send);
  int err = uv_udp_init(conn->loop, &conn->udp_handle);

  if (err) {
    return err;
  }

  struct sockaddr_in v4addr;
  struct sockaddr_in6 v6addr;
  if (proxy_addr != NULL) {
    printf("binding ipv4\n");
    err = uv_ip4_addr("0.0.0.0", 40026, &v4addr);
  }
  else {
    printf("binding ipv6\n");
    err = uv_ip6_addr("::", 40026, &v6addr);
  }

  const struct sockaddr *addr = proxy_addr != NULL ? (struct sockaddr*)&v4addr : (struct sockaddr*)&v6addr;

  uv_udp_bind(&conn->udp_handle, addr, UV_UDP_REUSEADDR);

  if (err != 0) {
    return err;
  }

  conn->udp_handle.data = conn;
  conn->proxy_addr = proxy_addr;
  conn->callback = callback;

  err = uv_udp_recv_start(&conn->udp_handle, _helium_buffer_alloc_callback, _helium_udp_recv_callback);
  if (err != 0) {
    return err;
  }

  // kick off the thread
 uv_thread_create(&conn->thread, _bootup, conn);
 
  return 0;
}

int helium_send(helium_connection_t *conn, uint64_t macaddr, helium_token_t token, char *message, size_t count)
{
  struct helium_send_req_s *req = malloc(sizeof(struct helium_send_req_s));
  req->macaddr = macaddr;
  memcpy(req->token, token, 16);
  req->message = malloc(count);
  memcpy(req->message, message, count);
  req->count = count;
  req->conn = conn;
  conn->async.data = (void*)req;
  uv_async_send(&conn->async);
  // TODO we should also pass our own async message thing and have our own libuv loop so we can stall here waiting for the reply
  return 0;
}

int helium_close(helium_connection_t *conn)
{
  uv_udp_recv_stop(&conn->udp_handle);

  return 0;
}

