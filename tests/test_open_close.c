#include <stdio.h>
#include <stdlib.h>

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "helium.h"

void test_freeing_null() {
  helium_free(NULL);
}

void test_alloc_then_free() {
  helium_connection_t *conn = helium_alloc();
  helium_free(conn);
}

int main(int argc, char *argv[])
{
  CU_pSuite pSuite = NULL;
  
  if (CUE_SUCCESS != CU_initialize_registry()) {
    return CU_get_error();
  }
 
   /* add a suite to the registry */ 
  pSuite = CU_add_suite("Suite_1", NULL, NULL);
  if (pSuite == NULL) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  typedef struct {
    char *message;
    void (*test)(void);
  } test_case;

  test_case ALL_CASES[] = {
    { .message = "helium_free(NULL) should be a no-op", .test = test_freeing_null },
    { .message = "alloc then free should have no footprint", .test = test_alloc_then_free },
  };

  for (size_t ii=0; ii < (sizeof(ALL_CASES) / sizeof(test_case)); ii++) {
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
  CU_cleanup_registry();
  return CU_get_error();
}

