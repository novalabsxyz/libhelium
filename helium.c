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
  printf("In allocation callback\n");
  char *chunk = malloc(size);
  assert(chunk != NULL);
  *buf = uv_buf_init(chunk, size);
}

void udp_recv_callback(uv_udp_t *handle, ssize_t count, const uv_buf_t *buf, const struct sockaddr *addr, unsigned int flags)
{
  if (count < 1) {
    return;
  }
  struct sockaddr_in *peer = (struct sockaddr_in*)addr;
  printf("In recv callback! %s\n", buf->base);

  uv_buf_t message = { "ping", 4 };

  uv_udp_send_t *send_request;
  send_request = malloc(sizeof(*send_request));
  int err = uv_udp_send(send_request, handle, &message, 1, addr, NULL);
  assert(!err);

}

void udp_send_callback(uv_udp_send_t *req, int status)
{
  printf("In send callback!\n");
}

uv_udp_t send_socket;
uv_udp_t recv_socket;

int main(int argc, char *argv[])
{
  loop = uv_default_loop();

  uv_udp_init(loop, &recv_socket);

  struct sockaddr_in bind_addr;
  int err = uv_ip4_addr("0.0.0.0", 40026, &bind_addr);
  assert(!err);

  err = uv_udp_bind(&recv_socket, (struct sockaddr*)&bind_addr, 0);
  assert(!err);

  err = uv_udp_recv_start(&recv_socket, allocation_callback, udp_recv_callback);
  assert(!err);

  uv_run(loop, UV_RUN_DEFAULT);

  return 0;
}
