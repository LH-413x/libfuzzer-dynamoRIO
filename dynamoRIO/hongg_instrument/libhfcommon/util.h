/*
 *
 * honggfuzz - utilities
 * -----------------------------------------
 *
 * Author: Robert Swiecki <swiecki@google.com>
 *
 * Copyright 2010-2018 by Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 *
 */

#ifndef _HF_COMMON_UTIL_H_
#define _HF_COMMON_UTIL_H_

#include <pthread.h>
#include <stdarg.h>
#ifdef __clang__
#include <stdatomic.h>
#endif
#include <stdbool.h>
#include <stdint.h>
#include <time.h>


#define ATOMIC_GET(x) __atomic_load_n(&(x), __ATOMIC_RELAXED)
#define ATOMIC_SET(x, y) __atomic_store_n(&(x), y, __ATOMIC_RELAXED)

#define ATOMIC_XCHG(x, y) __atomic_exchange_n(&(x), y, __ATOMIC_RELAXED)


#define ATOMIC_POST_ADD(x, y) __atomic_fetch_add(&(x), y, __ATOMIC_RELAXED)



#define ATOMIC_PRE_INC_RELAXED(x) __atomic_add_fetch(&(x), 1, __ATOMIC_RELAXED)
#define ATOMIC_POST_OR_RELAXED(x, y) __atomic_fetch_or(&(x), y, __ATOMIC_RELAXED)

__attribute__((always_inline)) static inline uint8_t ATOMIC_BTS(uint8_t* addr, size_t offset) {
    uint8_t oldbit;
    addr += (offset / 8);
    oldbit = ATOMIC_POST_OR_RELAXED(*addr, ((uint8_t)1U << (offset % 8)));
    return oldbit;
}




#endif /* ifndef _HF_COMMON_UTIL_H_ */
