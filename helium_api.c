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
};

int helium_init(helium_connection_t *conn, const char *ipv4_proxy_address)
{
  if (ipv4_proxy_address != NULL) {
    // set the ipv4 proxy here
  }

  conn->loop = uv_default_loop();
  uv_udp_init(conn->loop, &conn->udp_recv_handle);
  uv_udp_init(conn->loop, &conn->udp_send_handle);

  return 0;
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
  }
  
}

int helium_connect(helium_connection_t *conn, uint64_t macaddr, helium_callback_t callback)
{
  char *domain = NULL;

  asprintf(&domain, "%lX.d.helium.co", macaddr);

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

int helium_send(helium_connection_t *conn, uint64_t macaddr, helium_token_t token, const char *message, size_t count)
{
  // TODO
  return 0;
}
