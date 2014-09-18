#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <uv.h>
#include <assert.h>
#include <unistd.h>


uv_loop_t *loop = NULL;

const char* libhelium_version(void) 
{
  return LIBHELIUM_VERSION;
}

void allocation_callback(uv_handle_t *handle, size_t size, uv_buf_t *buf)
{
  printf("In allocation callback, allocating %d bytes\n", (int)size);
  char *chunk = malloc(size);
  assert(chunk != NULL);
  *buf = uv_buf_init(chunk, size);
}

void udp_send_callback(uv_udp_send_t *req, int status)
{
  printf("In send callback! %d\n", status);
  assert(!status);
  free(req);
}

void udp_recv_callback(uv_udp_t *handle, ssize_t count, const uv_buf_t *buf, const struct sockaddr *addr, unsigned int flags)
{
  if (count < 1) {
    return;
  }
  printf("In recv callback! Got %ld bytes, received text %s\n", count, buf->base);
  uv_buf_t message = { "pong", 4 };

  uv_udp_send_t *send_request;
  send_request = malloc(sizeof(*send_request));
  int err = uv_udp_send(send_request, handle, &message, 1, addr, NULL);
  assert(!err);
}

uv_udp_t send_socket;

int main(int argc, char *argv[])
{
  loop = uv_default_loop();

  uv_udp_init(loop, &send_socket);

  struct sockaddr_in bind_addr;
  struct sockaddr_in send_addr;
  int err = uv_ip4_addr("0.0.0.0", 40027, &bind_addr);
  assert(!err);

  err = uv_ip4_addr("127.0.0.1", 40026, &send_addr);
  assert(!err);

  err = uv_udp_bind(&send_socket, (struct sockaddr*)&bind_addr, UV_UDP_REUSEADDR);
  assert(!err);

  //uv_udp_set_broadcast(&send_socket, 1);

  uv_buf_t message = { "hello world", 11 };

  uv_udp_send_t send_request;
  err = uv_udp_send(&send_request, &send_socket, &message, 1, (struct sockaddr*)&send_addr, NULL);
  assert(!err);

  err = uv_udp_recv_start(&send_socket, allocation_callback, udp_recv_callback);
  assert(!err);

  //uv_udp_init(loop, &send_socket);

  printf("Entering libuv loop...\n");

  uv_run(loop, UV_RUN_DEFAULT);

  return 0;
}
