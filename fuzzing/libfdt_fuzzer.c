/*
 * Copyright (C) 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Ensure assert() catches logical errors during fuzzing */
#ifdef NDEBUG
#undef NDEBUG
#endif

#include <inttypes.h>
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include <sanitizer/asan_interface.h>
#include <sanitizer/msan_interface.h>

#include "libfdt.h"
#include "libfdt_env.h"

/* check memory region is valid, for the purpose of tooling such as asan */
static void check_mem(const void *mem, size_t len) {

  assert(mem);

#if __has_feature(memory_sanitizer)
  /* dumps if check fails */
  __msan_check_mem_is_initialized((void *)mem, len);
#endif

#if __has_feature(address_sanitizer) || defined(__SANITIZE_ADDRESS__)
  assert(!__asan_region_is_poisoned((void *)mem, len));
#else
  const volatile uint8_t *mem8 = mem;

  /* Read each byte of memory for instrumentation */
  for(size_t i = 0; i < len; i++) {
    (void)mem8[i];
  }
#endif
}

static bool phandle_is_valid(uint32_t phandle) {
  return phandle != 0 && phandle != UINT32_MAX;
}

static void walk_node_properties(const void *device_tree, int node) {
  int property, len = 0;

  fdt_for_each_property_offset(property, device_tree, node) {
    const struct fdt_property *prop = fdt_get_property_by_offset(device_tree,
                                                                 property, &len);
    if (!prop)
      continue;
    check_mem(prop->data, fdt32_to_cpu(prop->len));

    const char *prop_name = fdt_string(device_tree, prop->nameoff);
    if (prop_name != NULL) {
      check_mem(prop_name, strlen(prop_name));
    }
  }
}


static void walk_device_tree(const void *device_tree, int parent_node) {
  int len = 0;
  const char *node_name = fdt_get_name(device_tree, parent_node, &len);
  if (node_name != NULL) {
    check_mem(node_name, len);
  }

  uint32_t phandle = fdt_get_phandle(device_tree, parent_node);
  if (phandle_is_valid(phandle)) {
    int node = fdt_node_offset_by_phandle(device_tree, phandle);
    assert(node >= 0); // it should at least find parent_node
  }

  char path_buf[64];
  if(fdt_get_path(device_tree, parent_node, path_buf, sizeof(path_buf)) == 0) {
    fdt_path_offset(device_tree, path_buf);
  }

  fdt_parent_offset(device_tree, parent_node);

  // Exercise sub-node search string functions
  fdt_subnode_offset(device_tree, parent_node, "a");
  fdt_get_property(device_tree, parent_node, "reg", &len);

  // Check for a stringlist node called 'stringlist' (added to corpus)
  const int sl_count = fdt_stringlist_count(device_tree,
                                            parent_node, "stringlist");
  if (sl_count > 0) {
    for (int i = 0; i < sl_count; i++) {
      fdt_stringlist_get(device_tree, parent_node, "stringlist", i, &len);
    }

    fdt_stringlist_search(device_tree, parent_node, "stringlist", "a");
  }

  walk_node_properties(device_tree, parent_node);

  // recursively walk the node's children
  for (int node = fdt_first_subnode(device_tree, parent_node); node >= 0;
       node = fdt_next_subnode(device_tree, node)) {
    walk_device_tree(device_tree, node);
  }
}


static void walk_mem_rsv(const void *device_tree) {
  const int n = fdt_num_mem_rsv(device_tree);
  uint64_t address, size;

  for (int i = 0; i < n; i++) {
    fdt_get_mem_rsv(device_tree, i, &address, &size);
  }
}


// Information on device tree is available in external/dtc/Documentation/
// folder.
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  int rc;

  // Non-zero return values are reserved for future use.
  if (size < FDT_V17_SIZE) return 0;

  // Produce coverage of checking function
  rc = fdt_check_full(data, size);
  fdt_strerror(rc);

  // Don't continue if the library rejected the input
  if (rc != 0) return 0;

  // Cover reading functions
  walk_device_tree(data, /* parent_node */ 0);
  walk_mem_rsv(data);

  // Cover phandle functions
  uint32_t phandle;
  fdt_generate_phandle(data, &phandle);

  // Try and get a path by alias
  fdt_path_offset(data, "a");

  // Try to get an alias
  fdt_get_alias(data, "a");

  // Exercise common search functions
  fdt_node_offset_by_compatible(data, 0, "a");
  fdt_node_offset_by_prop_value(data, 0, "x", "42", 3);

  return 0;
}

