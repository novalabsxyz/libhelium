#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>


const char* libhelium_version(void) 
{
  return "0.0.1";
}

// encrypt a message into a packet
// this function mallocs its own output buffer into **dst
int libhelium_encrypt_packet(const char *token, const char *message, char **dst) {
  EVP_CIPHER_CTX *ctx;
  SHA256_CTX sha256;
  char fingerprint[SHA256_DIGEST_LENGTH];
  int outlen = 0;
  int tmplen = 0;
  char *tmpdst;
  unsigned char iv[12];
  if ((RAND_bytes((unsigned char*)&iv, 12)) != 1) {
    return -1;
  }

  *dst = malloc(strlen(message) + 12 + 16 + SHA256_DIGEST_LENGTH);
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
  EVP_EncryptUpdate(ctx, tmpdst, &outlen, message, strlen(message));
  EVP_EncryptFinal_ex(ctx, tmpdst, &tmplen);
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tmpdst+outlen);
  EVP_CIPHER_CTX_free(ctx);
  return outlen+16+SHA256_DIGEST_LENGTH+12;
}

// decrypt a message from a packet
// this function mallocs its own output buffer into **dst
int libhelium_decrypt_packet(const char *token, const char *packet, int packetlen, char **dst) {
  EVP_CIPHER_CTX *ctx;
  int outlen, tmplen, rv;
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
