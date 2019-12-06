/*
 *
 * honggfuzz - compiler instrumentation
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

#ifndef _HF_LIBHFUZZ_INSTRUMENT_H_
#define _HF_LIBHFUZZ_INSTRUMENT_H_

#include <inttypes.h>

void instrumentUpdateCmpMap(uintptr_t addr, uint32_t v);

void instrumentClearNewCov();
void __sanitizer_cov_trace_pc();
void __sanitizer_cov_trace_pc_guard_init(uint32_t* start, uint32_t* stop);
void __sanitizer_cov_trace_pc_guard(uint32_t* guard);

void __sanitizer_cov_trace_cmp8(uint64_t Arg1, uint64_t Arg2);
void __sanitizer_cov_trace_cmp4(uint32_t Arg1, uint32_t Arg2);
void __sanitizer_cov_trace_cmp2(uint16_t Arg1, uint16_t Arg2);
void __sanitizer_cov_trace_cmp1(uint8_t Arg1, uint8_t Arg2);

void __sanitizer_cov_trace_div4(uint32_t Val);
void __sanitizer_cov_trace_div8(uint64_t Val);

void __sanitizer_cov_trace_pc_indir(uintptr_t callee);
void __sanitizer_cov_indir_call16(void* callee, void* callee_cache16[] );

void if_hfuzz_trace_pc_internal(uintptr_t pc);


#endif /* ifdef _HF_LIBHFUZZ_INSTRUMENT_H_ */
