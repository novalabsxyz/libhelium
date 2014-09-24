#include <stdio.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

// crypto stuff
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "helium_internal.h"
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
  int finallen;
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
  ret = EVP_DecryptFinal_ex(ctx, *dst, &finallen);
  EVP_CIPHER_CTX_free(ctx);
  if (ret != 1) {
    return 0;
  }
  (*dst)[outlen] = '\0';
  return outlen;
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
  assert(handle->data != NULL);
  helium_connection_t *conn = (helium_connection_t *)handle->data;
  char *message = buf->base;

  if (conn->proxy_addr == NULL) {
    // extract from ipv6 peer address
    struct sockaddr_in6 *in6addr = (struct sockaddr_in6*)addr;
    memcpy((void*)&macaddr, in6addr->sin6_addr.s6_addr+8, 8);
    // XXX this is a giant non-portable hack
    macaddr = __builtin_bswap64(macaddr);
  } else {
    // the first 8 bytes are the MAC, little endian
    memcpy((void*)&macaddr, buf->base, 8);
    message += 8;
    nread -= 8;
  }

  unsigned char *out;
  struct helium_mac_token_map *entry = NULL;
  HASH_FIND(hh, conn->token_map, &macaddr, sizeof(macaddr), entry);

  if (!entry) {
    helium_log(LOG_ERR, "couldn't find entry in mac->token map for mac addr %lx", macaddr);
    return;
  }
  
  int res = libhelium_decrypt_packet(entry->token, (unsigned char*)message, nread, &out);
  if (res < 1) {
    helium_dbg("decryption failed %d\n", res);
    return;
  }
  helium_dbg("decryption result %d\n", res);
  helium_dbg("packet %s\n", out);

  helium_dbg("MAC is %lu\n", macaddr);

  // should we ever call this when nread < 1?
  conn->callback(conn, macaddr, (char*)out, res);
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

helium_connection_t *helium_alloc(void)
{
  return calloc(sizeof(helium_connection_t), 1);
}

void helium_free(helium_connection_t *conn)
{
  struct helium_mac_token_map *iter = NULL;
  struct helium_mac_token_map *tmp = NULL;

  HASH_ITER(hh, conn->token_map, iter, tmp) {
    HASH_DEL(conn->token_map, iter);
    free(iter);
  }
  
  free(conn);
}

int helium_init(helium_connection_t *conn, char *proxy_addr, helium_callback_t callback)
{
  // should we parameterize this function so as to allow a passed loop?
  conn->loop = uv_loop_new();
  conn->token_map = NULL;
  uv_async_init(conn->loop, &conn->async, _helium_do_udp_send);
  int err = uv_udp_init(conn->loop, &conn->udp_handle);

  if (err) {
    return err;
  }

  struct sockaddr_in v4addr;
  struct sockaddr_in6 v6addr;
  if (proxy_addr != NULL) {
    helium_dbg("binding ipv4");
    err = uv_ip4_addr("0.0.0.0", 0, &v4addr);
  }
  else {
    helium_dbg("binding ipv6");
    err = uv_ip6_addr("::", 0, &v6addr);
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
  unsigned char *packet;
  count = libhelium_encrypt_packet(token, message, &packet);
  if (count < 1) {
    return -1;
  }

  struct helium_mac_token_map *entry = malloc(sizeof(struct helium_mac_token_map));
  entry->mac = macaddr;
  memcpy(entry->token, token, sizeof(helium_token_t));

  struct helium_mac_token_map *old = NULL;
  HASH_REPLACE(hh, conn->token_map, mac, sizeof(uint64_t), entry, old);
  free(old); // no-op if old == NULL, otherwise frees the old entry

  struct helium_send_req_s *req = malloc(sizeof(struct helium_send_req_s));

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

