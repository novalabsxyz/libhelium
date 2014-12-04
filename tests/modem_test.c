/*
 * Copyright (C) 2014 Helium Systems Inc.
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "helium.h"

typedef struct {
  char *message;
  void (*test)(void);
} test_case;

int saw_message;
char random_string[16];

void handle_helium_message(const helium_connection_t *conn, uint64_t sender_mac, char * const message, size_t count) {
  saw_message++;
  printf("We saw a message and saw_message is: %i\n", saw_message);
}

void handle_helium_echo_message(const helium_connection_t *conn, uint64_t sender_mac, char * const message, size_t count) {
  if (strncmp(random_string, message, 16) == 0) {
    saw_message++;
  }
  printf("We saw a message %s and saw_message is: %i\n", (char*)message, saw_message);
}

void test_subscribe_get_message() {

  /* Create a connection */
  helium_connection_t *conn = helium_alloc();
  helium_token_t token;
  unsigned char *b64token;
  printf("Opening connection\n");
  helium_open(conn, NULL, handle_helium_message);

  b64token = (unsigned char*)"PbOkU4Jo+NObbPe27MJGNQ==";
  helium_base64_token_decode(b64token, strlen((char*)b64token), token);
  
  saw_message = 0;
  printf("Subscribing to device\n");
  helium_subscribe(conn, 0x000000fffff00002, token);

  sleep(6);

  helium_free(conn);
  CU_ASSERT(saw_message);
  
}

void test_subscribe_get_message_ipv4() {

  /* Create a connection */
  helium_connection_t *conn = helium_alloc();
  helium_token_t token;
  unsigned char *b64token;
  printf("Opening connection\n");
  helium_open(conn, "r01.sjc.helium.io", handle_helium_message);

  b64token = (unsigned char*)"PbOkU4Jo+NObbPe27MJGNQ==";
  helium_base64_token_decode(b64token, strlen((char*)b64token), token);
  
  saw_message = 0;
  printf("Subscribing to device\n");
  helium_subscribe(conn, 0x000000fffff00002, token);

  sleep(6);

  helium_free(conn);
  CU_ASSERT(saw_message);
}


void test_send_and_get_message() {
  /* init rand */
  time_t t;

  /* Create a connection */
  helium_connection_t *conn = helium_alloc();
  helium_token_t token;
  unsigned char *b64token;
  printf("Opening connection\n");
  helium_open(conn, NULL, handle_helium_echo_message);

  b64token = (unsigned char*)"gLXfMtbHEzto9AfiRfafww==";
  helium_base64_token_decode(b64token, strlen((char*)b64token), token);
  
  saw_message = 0;
  printf("Subscribing to device\n");
  helium_subscribe(conn, 0x000000fffff00001, token);

  srand((unsigned) time(&t));
  snprintf(random_string, sizeof(random_string), "Rand: %i", rand() % 128);

  printf("Sending to device\n");
  helium_send(conn, 0x000000fffff00001, token, (unsigned char*)random_string, strlen(random_string));

  sleep(6);

  helium_free(conn);
  CU_ASSERT(saw_message);
}

void test_send_and_get_message_ipv4() {
  /* init rand */
  time_t t;

  /* Create a connection */
  helium_connection_t *conn = helium_alloc();
  helium_token_t token;
  unsigned char *b64token;
  printf("Opening connection\n");
  helium_open(conn, "r01.sjc.helium.io", handle_helium_echo_message);

  b64token = (unsigned char*)"gLXfMtbHEzto9AfiRfafww==";
  helium_base64_token_decode(b64token, strlen((char*)b64token), token);
  
  saw_message = 0;
  printf("Subscribing to device\n");
  helium_subscribe(conn, 0x000000fffff00001, token);

  srand((unsigned) time(&t));
  snprintf(random_string, sizeof(random_string), "Rand: %i", rand() % 128);

  printf("Sending to device\n");
  helium_send(conn, 0x000000fffff00001, token, (unsigned char*)random_string, strlen(random_string));

  sleep(6);

  helium_free(conn);
  CU_ASSERT(saw_message);
}

int main(int argc, char *argv[])
{
  CU_pSuite pSuite = NULL;
  size_t ii;
  test_case ALL_CASES[4];
  unsigned int failures = 0;
  ALL_CASES[0].message = "we should get a simple helium message";
  ALL_CASES[0].test = test_subscribe_get_message;
  ALL_CASES[1].message = "we should get a simple helium message: ipv4";
  ALL_CASES[1].test = test_subscribe_get_message_ipv4;
  ALL_CASES[2].message = "test send & receive";
  ALL_CASES[2].test = test_send_and_get_message;
  ALL_CASES[3].message = "test send & receive: ipv4";
  ALL_CASES[3].test = test_send_and_get_message_ipv4;

  if (CUE_SUCCESS != CU_initialize_registry()) {
    return CU_get_error();
  }

   /* add a suite to the registry */
  pSuite = CU_add_suite("Suite_sweet", NULL, NULL);
  if (pSuite == NULL) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  for (ii=0; ii < (sizeof(ALL_CASES) / sizeof(test_case)); ii++) {
    test_case tc = ALL_CASES[ii];
    if (CU_add_test(pSuite, tc.message, tc.test) == NULL) {
      CU_cleanup_registry();
      return CU_get_error();
    }
  }

   /* add the tests to the suite */


  /* Run all tests using the CUnit Basic interface */
  CU_basic_set_mode(CU_BRM_VERBOSE);
  CU_basic_run_tests();

  failures = CU_get_number_of_failures();

  CU_cleanup_registry();

  return (int)failures;
}
