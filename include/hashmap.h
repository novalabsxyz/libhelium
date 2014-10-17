/*
    This file is part of the OpenOMF project: http://www.openomf.org/

    Copyright (C) 2097 Tuomas Virtanen, Andrew Thompson, Hunter and others

    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
    of the Software, and to permit persons to whom the Software is furnished to do
    so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

#ifndef _HASHMAP_H
#define _HASHMAP_H

#include <stdlib.h>
#include <math.h>

// iterator stuff

typedef struct iterator_t iterator;

struct iterator_t {
    const void *data;
    void *vnow;
    int inow;
    int ended;
    void* (*next)(iterator*);
    void* (*prev)(iterator*);
};

void* iter_next(iterator *iterator);
void* iter_prev(iterator *iterator);

typedef struct hashmap_pair_t hashmap_pair;
typedef struct hashmap_node_t hashmap_node;
typedef struct hashmap_t hashmap;

typedef struct allocator_t {
    void* (*cmalloc)(size_t size);
    void  (*cfree)(void *ptr);
    void* (*crealloc)(void *ptr, size_t size);
} allocator;

struct hashmap_pair_t {
    unsigned int keylen, vallen;
    void *key, *val;
};

struct hashmap_node_t {
    hashmap_pair pair;
    hashmap_node *next;
};

struct hashmap_t {
    hashmap_node **buckets;
    unsigned int buckets_x;
    unsigned int reserved;
    allocator alloc;
};

void hashmap_create(hashmap *hashmap, int n_size); // actual size will be 2^n_size
void hashmap_create_with_allocator(hashmap *hashmap, int n_size, allocator alloc);
void hashmap_free(hashmap *hashmap);
unsigned int hashmap_size(const hashmap *hashmap);
unsigned int hashmap_reserved(const hashmap *hashmap);
void* hashmap_put(hashmap *hm, const void *key, unsigned int keylen, const void *val, unsigned int vallen);
void hashmap_sput(hashmap *hashmap, const char *key, void *value, unsigned int value_len);
void hashmap_iput(hashmap *hashmap, unsigned int key, void *value, unsigned int value_len);
int hashmap_get(hashmap *hm, const void *key, unsigned int keylen, void **val, unsigned int *vallen);
int hashmap_sget(hashmap *hashmap, const char *key, void **value, unsigned int *value_len);
int hashmap_iget(hashmap *hashmap, unsigned int key, void **value, unsigned int *value_len);
int hashmap_del(hashmap *hm, const void *key, unsigned int keylen);
void hashmap_sdel(hashmap *hashmap, const char *key);
void hashmap_idel(hashmap *hashmap, unsigned int key);
void hashmap_iter_begin(const hashmap *hashmap, iterator *iter);
int hashmap_delete(hashmap *hashmap, iterator *iter);
void hashmap_clear(hashmap *hashmap);

#endif // _HASHMAP_H
