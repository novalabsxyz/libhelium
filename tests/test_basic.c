/*
 * Copyright (C) 2014 Helium Systems Inc.
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#include <stdio.h>
#include <stdlib.h>

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "helium.h"

typedef struct {
  char *message;
  void (*test)(void);
} test_case;

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
  size_t ii;
  test_case ALL_CASES[2];
  unsigned int failures = 0;
  ALL_CASES[0].message = "helium_free(NULL) should be a no-op";
  ALL_CASES[0].test = test_freeing_null;
  ALL_CASES[1].message = "alloc then free should have no footprint";
  ALL_CASES[1].test = test_alloc_then_free;


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
