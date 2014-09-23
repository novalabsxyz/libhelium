#include <stdio.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

// crypto stuff
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "helium.h"
#include "logging.h"

const char *libhelium_version()
{
  return LIBHELIUM_VERSION;
}

// encrypt a message into a packet
// this function mallocs its own output buffer into **dst
int libhelium_encrypt_packet(const unsigned char *token, const unsigned char *message, unsigned char **dst) {
  EVP_CIPHER_CTX *ctx;
  SHA256_CTX sha256;
  int outlen = 0;
  int tmplen = 0;
  unsigned char *tmpdst;
  unsigned char iv[12];
  if ((RAND_bytes((unsigned char*)&iv, 12)) != 1) {
    return -1;
  }

  *dst = malloc(strlen((char*)message) + 12 + 16 + SHA256_DIGEST_LENGTH);
  tmpdst = *dst;

  SHA256_Init(&sha256);
  SHA256_Update(&sha256, token, 16);
  SHA256_Final(tmpdst, &sha256);
  tmpdst += SHA256_DIGEST_LENGTH;
  memcpy(tmpdst, iv, 12);
  tmpdst += 12;

  ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL);
  EVP_EncryptInit_ex(ctx, NULL, NULL, token, iv);
  // no AAD
  EVP_EncryptUpdate(ctx, tmpdst, &outlen, message, strlen((char*)message));
  EVP_EncryptFinal_ex(ctx, tmpdst, &tmplen);
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tmpdst+outlen);
  EVP_CIPHER_CTX_free(ctx);
  return outlen+16+SHA256_DIGEST_LENGTH+12;
}

// decrypt a message from a packet
// this function mallocs its own output buffer into **dst
int libhelium_decrypt_packet(const unsigned char *token, const unsigned char *packet, int packetlen, unsigned char **dst) {
  EVP_CIPHER_CTX *ctx;
  int outlen;
  unsigned char iv[12];
  unsigned char tag[16];
  int ret;

  // pull the IV off the packet
  memcpy(iv, packet, 12);

  memcpy(tag, packet+(packetlen-16), 16);

  packet += 12;
  packetlen -= 16+12;

  *dst = (malloc(packetlen+1));

  ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL);
  EVP_DecryptInit_ex(ctx, NULL, NULL, token, iv);

  EVP_DecryptUpdate(ctx, *dst, &outlen, packet, packetlen);
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, sizeof(tag), tag);
  ret = EVP_DecryptFinal_ex(ctx, *dst, &outlen);
  EVP_CIPHER_CTX_free(ctx);
  return ret;
}

struct helium_send_req_s {
  uint64_t macaddr;
  helium_token_t token;
  char *message;
  size_t count;
  helium_connection_t *conn;
};

void _helium_buffer_alloc_callback(uv_handle_t *handle, size_t suggested, uv_buf_t *dst)
{
  helium_dbg("in allocate, allocating %zd bytes", suggested);
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
    helium_log(LOG_ERR, "Error in Helium callback: getnameinfo failed, reason: %s", err);
    return;
  }

  if (strncmp(host, "localhost", BUFLEN) == 0) {
    // testing
    helium_dbg("from localhost, just testing");
    strcpy(host, "deadbeef.d.helium.co");
  }

  helium_dbg("Received host is %s\n", host);

  unsigned int whatever = 0;
  err = sscanf(host, "%x.d.helium.co", &whatever);
  macaddr = whatever;
  
  if (err == 0) {
    helium_log(LOG_WARNING, "Couldn't extract mac address from host %s\n", host);
  } else {
    helium_dbg("Extracted MAC is %lX\n", macaddr);
  }

  // should we ever call this when nread < 1?
  conn->callback(conn, macaddr, buf->base, nread);
}

#if HAVE_BLOCKS
void _helium_block_callback(const helium_connection_t *conn, uint64_t sender_mac, char * const message, size_t count)
{
  conn->callback_block(conn, sender_mac, message, count);
}
#endif

void _helium_send_callback(uv_udp_send_t *req, int status)
{

  helium_dbg("In send callback, sent %d\n", status);
  if (status == 0) {
    free(req);
  }
}

void _helium_do_udp_send(uv_async_t *handle)
{
  struct helium_send_req_s *req = (struct helium_send_req_s*)handle->data;
  helium_connection_t *conn = req->conn;
  char *target = NULL;
  struct addrinfo hints = {AF_UNSPEC, SOCK_DGRAM, 0, 0};
  if (conn->proxy_addr == NULL) {
    asprintf(&target, "%lX.d.helium.io", req->macaddr);
    helium_dbg("looking up %s", target);
    if (target == NULL) {
      return;
    }
    // only return ipv6 addresses
    hints.ai_family = AF_INET6;
  } else {
    printf("using ipv4 proxy\n");
    target = conn->proxy_addr;
    hints.ai_family=AF_INET;
    // make room for prefixing the MAC onto the packet
    req->message = realloc(req->message, req->count+8);
    memmove(req->message+8, req->message, req->count);
    memcpy(req->message, (void*)&req->macaddr, 8);
    req->count += 8;
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

void _bootup(void *arg)
{
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
    helium_dbg("binding ipv4");
    err = uv_ip4_addr("0.0.0.0", 40026, &v4addr);
  }
  else {
    helium_dbg("binding ipv6");
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

#if HAVE_BLOCKS

int helium_init_b(helium_connection_t *conn, char *proxy_addr, helium_block_t block)
{
  conn->callback_block = block; // Block_copy(block) here??
  return helium_init(conn, proxy_addr, _helium_block_callback);
}

#endif

int helium_send(helium_connection_t *conn, uint64_t macaddr, helium_token_t token, unsigned char *message, size_t count)
{
  struct helium_send_req_s *req = malloc(sizeof(struct helium_send_req_s));

  unsigned char *packet;
  count = libhelium_encrypt_packet(token, message, &packet);
  if (count < 1) {
    return -1;
  }

  req->macaddr = macaddr;
  memcpy(req->token, token, 16);
  req->message = malloc(count);
  memcpy(req->message, packet, count);
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

