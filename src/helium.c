#include <stdio.h>
#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

// crypto stuff
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "helium_internal.h"

uv_loop_t __helium_default_loop;
uv_thread_t __helium_loop_runner_thread;
uv_idle_t __helium_loop_idler;

const char *libhelium_version()
{
  return LIBHELIUM_VERSION;
}

void helium_log(int priority, const char *format, ...)
{
  va_list args;
  va_start(args, format);
  vsyslog(priority, format, args);
}

void helium_dbg(const char *format, ...)
{
  va_list args;
  va_start(args, format);
  vsyslog(LOG_DEBUG, format, args);
}

// invoked via __helium_loop_runner_thread
void _run_default_loop(void *unused)
{
  uv_run(&__helium_default_loop, UV_RUN_DEFAULT);
}

// invoked by atexit(3)
void _teardown_default_loop(void)
{

  // Kill the idling process
  uv_idle_stop(&__helium_loop_idler);

  // And the loop
  uv_stop(&__helium_default_loop);
  uv_loop_close(&__helium_default_loop);

  uv_thread_join(&__helium_loop_runner_thread);
}

void _do_nothing(uv_idle_t *unused)
{

}

void _start_default_loop(void)
{
  uv_loop_init(&__helium_default_loop);
  uv_idle_init(&__helium_default_loop, &__helium_loop_idler);
  uv_idle_start(&__helium_loop_idler, _do_nothing);
  uv_thread_create(&__helium_loop_runner_thread, _run_default_loop, NULL);
  atexit(_teardown_default_loop);
}

uv_loop_t *helium_default_loop(void)
{
  static uv_once_t once = UV_ONCE_INIT;
  uv_once(&once, _start_default_loop);
  printf("Helium struct is %ld bytes\n", sizeof(helium_connection_t));

  return &__helium_default_loop;
}

// encrypt a message into a packet
// this function mallocs its own output buffer into **dst
int libhelium_encrypt_packet(const unsigned char *token, const unsigned char *message, char prefix, unsigned char **dst) {
  EVP_CIPHER_CTX *ctx;
  SHA256_CTX sha256;
  int outlen = 0;
  int tmplen = 0;
  unsigned char *tmpdst;
  unsigned char iv[12];
  // not doing a memset here may generate some uninitalized byte warnings in valgrind, but
  // since openssl mixes the random contents of the buffer into the entropy pool, it is probably ok?
  //memset(iv, 0, 12);
  if ((RAND_bytes(iv, 12)) != 1) {
    return -1;
  }
  size_t len = 1+ strlen((char*)message) + 12 + 16 + SHA256_DIGEST_LENGTH;
  *dst = malloc(len);
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
  EVP_EncryptUpdate(ctx, tmpdst, &outlen, (unsigned char*)&prefix, 1);
  tmpdst++;
  EVP_EncryptUpdate(ctx, tmpdst, &outlen, message, strlen((char*)message));
  EVP_EncryptFinal_ex(ctx, tmpdst, &tmplen);
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tmpdst+outlen);
  EVP_CIPHER_CTX_free(ctx);
  return outlen+1+16+SHA256_DIGEST_LENGTH+12;
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

int _helium_getdeviceaddr(uint64_t macaddr, char *proxy, struct addrinfo **address) {
  char *target;
  struct addrinfo hints = {AF_UNSPEC, SOCK_DGRAM, 0, 0};
  if (proxy == NULL) {
    asprintf(&target, "%" PRIX64 ".d.helium.io", macaddr);
    helium_dbg("looking up %s", target);
    if (target == NULL) {
      return -1;
    }
    // only return ipv6 addresses
    hints.ai_family = AF_INET6;
  } else {
    helium_dbg("using ipv4 proxy\n");
    target = proxy;
    hints.ai_family=AF_INET;
  }

  int err = getaddrinfo(target, "2169", &hints, address);

  if(proxy == NULL) {
    free(target);
  }

  return err;
}

void _helium_async_callback(uv_async_t *async)
{
  helium_dbg("In async callback");
  struct helium_request_s *request = (struct helium_request_s *)async->data;
  assert(request != NULL);

  helium_connection_t *conn = request->conn;
  uint64_t macaddr = request->macaddr;
  int result = 0;

  assert(conn != NULL);

  switch (request->request_type) {
  case SUBSCRIBE_REQUEST:
    result = _handle_subscribe_request(conn, macaddr, request->token);
    break;
  case SEND_REQUEST:
    result = _handle_send_request(conn, macaddr, request->token, request->message, request->count);
    break;
  case QUIT_REQUEST:
    result = _handle_quit(conn);
    break;
  case UNSUBSCRIBE_REQUEST:
    break; // currently not implemented
  }

  uv_sem_post(&conn->sem);

  if (result == 0) {
    free(request);
  }
}

void _helium_buffer_alloc_callback(uv_handle_t *handle, size_t suggested, uv_buf_t *dst)
{
  char *chunk = malloc(suggested);
  helium_dbg("in allocate, allocating %zd bytes into pointer %p", suggested, chunk);
  assert(chunk != NULL);
  memset(chunk, 0, suggested);
  *dst = uv_buf_init(chunk, suggested);
}

void _helium_run_callback(uv_work_t *req) {

  struct helium_callback_invocation_s *inc = req->data;
  helium_connection_t *conn = (helium_connection_t *)inc->conn;
  conn->callback(conn, inc->mac, inc->message, inc->res);
}

void _helium_after_callback(uv_work_t *req, int status) {
  struct helium_callback_invocation_s *inc = req->data;
  free(inc->message);
  free(inc);
  free(req);
}

void _helium_udp_recv_callback(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned int flags)
{
  if (nread == 0) {
    free(buf->base);
    return;
  }

  helium_dbg("in recv callback, buf chunk is %p", buf->base);
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

  unsigned char *out = NULL;
  struct helium_mac_token_map *entry = NULL;
  HASH_FIND(hh, conn->token_map, &macaddr, sizeof(macaddr), entry);

  if (!entry) {
    HASH_FIND(hh, conn->subscription_map, &macaddr, sizeof(macaddr), entry);
    if (!entry) {
      helium_log(LOG_ERR, "couldn't find entry in mac->token map for mac addr %" PRIx64, macaddr);
      return;
    }
  }

  int res = libhelium_decrypt_packet(entry->token, (unsigned char*)message, nread, &out);
  if (res < 1) {
    helium_dbg("decryption failed %d\n", res);
    free(out);
    return;
  }

  helium_dbg("decryption result %d\n", res);
  helium_dbg("packet %s\n", out);


  if (macaddr & 0x100000000000000) {
      // multicast bit is set, this is a group
      // TODO should we also pass the group MAC to the callback?
      helium_dbg("message is from a group\n");
      helium_dbg("Group MAC is %" PRIu64 "\n", macaddr);
      memcpy((void*)&macaddr, out, 8);
      res -= 8;
      memmove(out, out+8, res);
      out = realloc(out, res);
  }

  helium_dbg("device MAC is %" PRIu64 "\n", macaddr);

  // should we ever call this when nread < 1?
  //conn->callback(conn, macaddr, (char*)out, res);
  uv_work_t *req = malloc(sizeof(uv_work_t));
  struct helium_callback_invocation_s *inc = malloc(sizeof(struct helium_callback_invocation_s));
  inc->conn = conn;
  inc->mac = macaddr;
  inc->res = res;
  inc->message = (char*)out;
  req->data = inc;
  uv_queue_work(conn->loop, req, _helium_run_callback, _helium_after_callback);
  //free(out);
  free(buf->base);

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
    free(req->data);
    free(req);
  }
}

void _helium_refresh_subscriptions(uv_timer_t *handle) {
  helium_connection_t *conn = handle->data;
  helium_dbg("subscription refresh timer fired\n");
  struct helium_mac_token_map *s;
  size_t count;
  unsigned char *packet = NULL;
  struct addrinfo *address = NULL;
  int err;
  for(s=conn->subscription_map; s != NULL; s=s->hh.next) {
    packet=NULL;
    count = libhelium_encrypt_packet(s->token, (unsigned char*)"", 's', &packet);
    if (count < 1) {
      helium_dbg("failed to encrypt re-subscription packet for %" PRIu64 "\n", s->mac);
      continue;
    }
    err = _helium_getdeviceaddr(s->mac, conn->proxy_addr, &address);
    if (err == 0) {
      if (conn->proxy_addr != NULL) {
        // make room for prefixing the MAC onto the packet
        packet = realloc(packet, count+8);
        memmove(packet+8, packet, count);
        memcpy(packet, (void*)&s->mac, 8);
        count += 8;
      }
      uv_buf_t buf = { (char*)packet, count };
      uv_udp_send_t *send_req = malloc(sizeof(uv_udp_send_t));
      send_req->data = packet;
      uv_udp_send(send_req, &conn->udp_handle, &buf, 1, address->ai_addr, _helium_send_callback);
      helium_dbg("resubscribed to %" PRIu64 "\n", s->mac);
      freeaddrinfo(address);
    } else {
      free(packet);
    }
  }
}

int _handle_quit(helium_connection_t *conn)
{
    // stop UDP and the resubscription timer
  uv_udp_recv_stop(&conn->udp_handle);
  uv_timer_stop(&conn->subscription_timer);
  // unref all the handles
  uv_unref((uv_handle_t*)&conn->udp_handle);
  uv_unref((uv_handle_t*)&conn->subscription_timer);
  uv_unref((uv_handle_t*)&conn->async_handle);
  
  return 0;
}

int _handle_subscribe_request(helium_connection_t *conn,
                              uint64_t macaddr,
                              helium_token_t token)
{
    // keep track of the token, so we can decrypt replies
  struct helium_mac_token_map *entry = malloc(sizeof(struct helium_mac_token_map));
  entry->mac = macaddr;
  memcpy(entry->token, token, sizeof(helium_token_t));

  struct helium_mac_token_map *old = NULL;
  HASH_REPLACE(hh, conn->subscription_map, mac, sizeof(uint64_t), entry, old);
  free(old); // no-op if old == NULL, otherwise frees the old entry


  struct addrinfo *address = NULL;
  unsigned char *packet = NULL;
  int err;
  size_t count;
  
  count = libhelium_encrypt_packet(token, (unsigned char*)"", 's', &packet);
  if (count < 1) {
    helium_dbg("failed to encrypt ubscription packet for %" PRIu64 "\n", macaddr);
    return -1;
  }
  
  err = _helium_getdeviceaddr(macaddr, conn->proxy_addr, &address);
  if (err == 0) {
    if (conn->proxy_addr != NULL) {
      // make room for prefixing the MAC onto the packet
      packet = realloc(packet, count+8);
      memmove(packet+8, packet, count);
      memcpy(packet, (void*)&macaddr, 8);
      count += 8;
    }
    uv_buf_t buf = { (char*)packet, count };
    uv_udp_send_t *send_req = malloc(sizeof(uv_udp_send_t));
    send_req->data = packet;
    uv_udp_send(send_req, &conn->udp_handle, &buf, 1, address->ai_addr, _helium_send_callback);
    helium_dbg("subscribed to %" PRIu64 "\n", macaddr);
    freeaddrinfo(address);
  } else {
    helium_dbg("Couldn't get device addr");
    free(packet);
  }
  
  return 0;
}

int _handle_send_request(helium_connection_t *conn,
                         uint64_t macaddr,
                         helium_token_t token,
                         unsigned char *message,
                         size_t count)
{
  // keep track of the token, so we can decrypt replies
  struct helium_mac_token_map *entry = malloc(sizeof(struct helium_mac_token_map));
  entry->mac = macaddr;
  memcpy(entry->token, token, sizeof(helium_token_t));

  struct helium_mac_token_map *old = NULL;
  HASH_REPLACE(hh, conn->token_map, mac, sizeof(uint64_t), entry, old);
  free(old); // no-op if old == NULL, otherwise frees the old entry

  struct addrinfo *address = NULL;
  int err = _helium_getdeviceaddr(macaddr, conn->proxy_addr, &address);

  if (err != 0) {
    return err;
  }

  if (conn->proxy_addr != NULL) {
    // make room for prefixing the MAC onto the packet
    message = realloc(message, count+8);
    memmove(message+8, message, count);
    memcpy(message, (void*)&macaddr, 8);
    count += 8;
  }

  uv_buf_t buf = { (char *)message, count };
  uv_udp_send_t *send_req = malloc(sizeof(uv_udp_send_t));
  send_req->data = message;
  uv_udp_send(send_req, &conn->udp_handle, &buf, 1, address->ai_addr, _helium_send_callback);
  freeaddrinfo(address);

  return 0;
}

void _bootup(void *arg)
{
  helium_connection_t *conn = (helium_connection_t *)arg;
  uv_run(conn->loop, UV_RUN_DEFAULT);
}

helium_connection_t *helium_alloc(uv_loop_t *loop)
{
  helium_connection_t *conn = calloc(sizeof(helium_connection_t), 1);
  if (loop == NULL) {
    loop = helium_default_loop();
  }
  conn->loop = loop;
  // TODO: do we need to increment the refcount of the loop
  // (and decrement it in helium_free?)
  return conn;
}

void helium_free(helium_connection_t *conn)
{
  struct helium_mac_token_map *iter = NULL;
  struct helium_mac_token_map *tmp = NULL;

  HASH_ITER(hh, conn->token_map, iter, tmp) {
    HASH_DEL(conn->token_map, iter);
    free(iter);
  }

  struct helium_mac_token_map *iter2 = NULL;
  struct helium_mac_token_map *tmp2 = NULL;

  HASH_ITER(hh, conn->subscription_map, iter2, tmp2) {
    HASH_DEL(conn->subscription_map, iter2);
    free(iter2);
  }

  uv_sem_destroy(&conn->sem);
  uv_mutex_destroy(&conn->mutex);

  free(conn);
}

int helium_open(helium_connection_t *conn, const char *proxy_addr, helium_callback_t callback)
{
  conn->token_map = NULL;
  conn->subscription_map = NULL;
  uv_async_init(conn->loop, &conn->async_handle, _helium_async_callback);
  uv_timer_init(conn->loop, &conn->subscription_timer);
  uv_sem_init(&conn->sem, 0);
  uv_mutex_init(&conn->mutex);
  conn->subscription_timer.data = conn;
  uv_timer_start(&conn->subscription_timer, _helium_refresh_subscriptions, 30000, 30000);
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
  conn->callback = callback;

  if (proxy_addr) {
    conn->proxy_addr = malloc(strlen(proxy_addr)+1);
    strcpy(conn->proxy_addr, proxy_addr);
  }

  err = uv_udp_recv_start(&conn->udp_handle, _helium_buffer_alloc_callback, _helium_udp_recv_callback);
  if (err != 0) {
    return err;
  }

  return 0;
}

int helium_subscribe(helium_connection_t *conn, uint64_t macaddr, helium_token_t token)
{
  struct helium_request_s *req = malloc(sizeof(struct helium_request_s));
  
  req->request_type = SUBSCRIBE_REQUEST;
  req->macaddr = macaddr;
  memcpy(req->token, token, 16);
  req->conn = conn;
  uv_mutex_lock(&conn->mutex);

  conn->async_handle.data = req;
  uv_async_send(&conn->async_handle);
  // wait for the event loop to call sem_post on this semaphore
  uv_sem_wait(&conn->sem);
  uv_mutex_unlock(&conn->mutex);
  return 0;
}

void *helium_get_context(const helium_connection_t * conn)
{
  return conn->context;
}

void helium_set_context(helium_connection_t *conn, void *newcontext)
{
  conn->context = newcontext;
}

#if HAVE_BLOCKS

int helium_open_b(helium_connection_t *conn, char *proxy_addr, helium_block_t block)
{
  conn->callback_block = block; // Block_copy(block) here??
  return helium_init(conn, proxy_addr, _helium_block_callback);
}

#endif

int helium_send(helium_connection_t *conn, uint64_t macaddr, helium_token_t token, unsigned char *message, size_t count)
{
  unsigned char *packet = NULL;
  count = libhelium_encrypt_packet(token, message, 'd', &packet);
  if (count < 1) {
    return -1;
  }

  struct helium_request_s *req = malloc(sizeof(struct helium_request_s));
  req->request_type = SEND_REQUEST;
  req->macaddr = macaddr;
  memcpy(req->token, token, 16);
  
  req->message = packet;
  req->count = count;
  req->conn = conn;


  uv_mutex_lock(&conn->mutex);

  conn->async_handle.data = (void*)req;
  uv_async_send(&conn->async_handle);

  // wait for the event loop to call sem_post on this semaphore
  uv_sem_wait(&conn->sem);
  uv_mutex_unlock(&conn->mutex);

  return 0;
}

int helium_close(helium_connection_t *conn)
{
  struct helium_request_s *request = calloc(1, sizeof(struct helium_request_s));
  request->conn = conn;
  request->request_type = QUIT_REQUEST;
  
  uv_mutex_lock(&conn->mutex);
  conn->async_handle.data = request;
  uv_async_send(&conn->async_handle);
  // wait for the event loop to call sem_post on this semaphore
  uv_sem_wait(&conn->sem);
  uv_mutex_unlock(&conn->mutex);

  free(conn->proxy_addr);

  return 0;
}

int helium_base64_token_decode(const unsigned char *input, int length, helium_token_t token_out)
{
  BIO *b64, *bmem, *decoder;

  b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  bmem = BIO_new_mem_buf((void *)input, length);
  decoder = BIO_push(b64, bmem);
  BIO_flush(decoder);
  int readlen = BIO_read(decoder, token_out, length);
  BIO_free_all(b64);
  return readlen;
}
