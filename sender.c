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
  printf("In recv callback! Got %ld packets, received text %s\n", count, buf->base);
}

void udp_send_callback(uv_udp_send_t *req, int status)
{
  printf("In send callback!\n");
}

uv_udp_t send_socket;

int main(int argc, char *argv[])
{
  loop = uv_default_loop();
  
  uv_udp_init(loop, &send_socket);
  
  struct sockaddr_in bind_addr;
  int err = uv_ip4_addr("255.255.255.255", 40026, &bind_addr);
  assert(!err);
  
  err = uv_udp_bind(&send_socket, (struct sockaddr*)&bind_addr, UV_UDP_REUSEADDR);
  assert(!err);
  
  uv_udp_set_broadcast(&send_socket, 1);
  
  uv_buf_t message = { "hello world", 11 };
  
  uv_udp_send_t send_request;
  err = uv_udp_send(&send_request, &send_socket, &message, 1, (struct sockaddr*)&bind_addr, NULL);
  assert(!err);
  
  
  
  printf("Entering libuv loop...\n");

  uv_run(loop, UV_RUN_DEFAULT);

  return 0;
}
