#include <stdio.h>
#include <stdlib.h>

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "helium.h"

typedef struct {
  char *message;
  void (*test)(void);
} test_case;

void test_simple_decode()
{
  const char *input = "ZGVhZGJlZWZkZWFkYmVlZg==";
  const char *expected = "deadbeefdeadbeef";
  helium_token_t token;

  helium_base64_token_decode((const unsigned char *)input, strlen(input), token);
  CU_ASSERT_NSTRING_EQUAL(token, expected, 16);
}

int main(int argc, char *argv[])
{
  CU_pSuite pSuite = NULL;
  size_t ii;
  test_case ALL_CASES[1];
  unsigned int failures = 0;
  ALL_CASES[0].message = "simple base64 decoding should work";
  ALL_CASES[0].test = test_simple_decode;

  
  if (CUE_SUCCESS != CU_initialize_registry()) {
    return CU_get_error();
  }
 
   /* add a suite to the registry */ 
  pSuite = CU_add_suite("Suite_1", NULL, NULL);
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

