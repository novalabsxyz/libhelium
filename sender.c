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

void reading_callback(uv_stream_t *stream, ssize_t count, const uv_buf_t *buf)
{
  printf("In reading callback");
  fflush(stdout);
  if (count == UV_EOF) {
    printf("Hit EOF\n");
    uv_close((uv_handle_t *)stream, NULL);
  }
  else if (count > 0) {
    printf("Got %ld bytes\n", count);
    printf("Contents: %s", buf->base);
  }
}

void allocation_callback(uv_handle_t *handle, size_t size, uv_buf_t *buf)
{
  printf("In allocation callback");
  char *chunk = malloc(size);
  assert(chunk != NULL);
  *buf = uv_buf_init(chunk, size);
}

void connection_callback(uv_stream_t *server, int status)
{
  printf("In connection callback");
  uv_udp_t *client = malloc(sizeof(uv_udp_t));
  assert(client != NULL);
  uv_udp_init(loop, client);

  int err = uv_accept(server, (uv_stream_t*)client);
  if (err) {
    printf("Error accepting connection\n");
    uv_close((uv_handle_t*)client, NULL);
  }
  else {
    uv_read_start((uv_stream_t*)client, allocation_callback, reading_callback);
  }

  
  printf("In connection callback!\n");
}

void set_broadcast(uv_udp_t *send_socket) {
  struct sockaddr_in broadcast_addr;

  // The IP address 0.0.0.0 is used to bind to all interfaces.
  // Port 0 means that the OS randomly assigns a port.
  uv_ip4_addr("0.0.0.0", 0, &broadcast_addr);

  //  init, bind, broadcast
  uv_udp_init(loop, send_socket);
  uv_udp_bind(send_socket, (const struct sockaddr*)&broadcast_addr, 0);
  uv_udp_set_broadcast(send_socket, 1);
}

void send_callback(uv_udp_send_t *req, int status) {
  printf("In send callback! status is %d\n", status);
}

int main(int argc, char *argv[])
{
  loop = uv_default_loop();
  
  uv_udp_t server;
  uv_udp_init(loop, &server);

  struct sockaddr_in bind_addr;
  int err = uv_ip4_addr("0.0.0.0", 40026, &bind_addr);
  assert(!err);
  set_broadcast(&server);

  uv_buf_t to_send = uv_buf_init("wooo", 4);
  
  uv_udp_send_t send_request;
  err = uv_udp_send(&send_request, &server, &to_send, 1, (struct sockaddr*)&bind_addr, send_callback);
  assert(!err);
  
  uv_run(loop, UV_RUN_DEFAULT);

  return 0;
}
