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

void connected_callback(uv_connect_t *connection, int status)
{
  printf("Connected!\n");
}

void send_callback(uv_udp_send_t *req, int status) {
  printf("In send callback! status is %d\n", status);
}

void writing_callback(uv_write_t *write_request, int status) {
  printf("In writing callback!\n");
}

int main(int argc, char *argv[])
{
  loop = uv_default_loop();
  
  uv_tcp_t client;
  uv_tcp_init(loop, &client);

  struct sockaddr_in bind_addr;
  int err = uv_ip4_addr("0.0.0.0", 40026, &bind_addr);
  assert(!err);

  uv_connect_t connection;
  uv_tcp_connect(&connection, &client, (struct sockaddr*)&bind_addr, connected_callback);

  uv_buf_t to_send = uv_buf_init("wooo", 4);
  
  uv_write_t write_request;
  err = uv_write(&write_request, (uv_stream_t*)&client, &to_send, 1, writing_callback);
  assert(!err);
  
  uv_run(loop, UV_RUN_DEFAULT);

  return 0;
}
