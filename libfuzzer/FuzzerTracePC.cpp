//===- FuzzerTracePC.cpp - PC tracing--------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
// Trace PCs.
// This module implements __sanitizer_cov_trace_pc_guard[_init],
// the callback required for -fsanitize-coverage=trace-pc-guard instrumentation.
//
//===----------------------------------------------------------------------===//

#include "FuzzerTracePC.h"
#include "FuzzerBuiltins.h"
#include "FuzzerBuiltinsMsvc.h"
#include "FuzzerCorpus.h"
#include "FuzzerDefs.h"
#include "FuzzerDictionary.h"
#include "FuzzerExtFunctions.h"
#include "FuzzerIO.h"
#include "FuzzerUtil.h"
#include "FuzzerValueBitMap.h"
#include <set>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/types.h>

#include <iostream>

// Used by -fsanitize-coverage=stack-depth to track stack depth
ATTRIBUTES_INTERFACE_TLS_INITIAL_EXEC uintptr_t __sancov_lowest_stack;

#define __NR_memfd_create 319
#define _HF_BITMAP_FD 1023
#define _HF_VALUE_PROFILE_MAP_FD 1000
#define _HF_TORC8_FD 1001
#define _HF_TORC4_FD 1002
#define _HF_DATA_COPY_FD 1021

void* files_mapSharedMem(size_t sz, int* fd, const char* name) {
  *fd = syscall(__NR_memfd_create, name, (uintptr_t)MFD_CLOEXEC);
  if(*fd==-1) {
    std::cout << "__NR_memfd_create fail" << std::endl;
  }
  if(-1 == ftruncate(*fd, sz)){
    std::cout << "ftruncate(fd, sz)" << std::endl;
  }
  uint8_t* ret = (uint8_t*)mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_SHARED , *fd, 0);
  if(MAP_FAILED == ret) {
    perror("mmap");
  }
  return ret;
}

namespace fuzzer {

TracePC TPC;

size_t TracePC::GetTotalPCCoverage() {
  return ObservedPCs.size();
}

void TracePC::CreateModule(uint8_t* & data_copy) {
  int Modules_fd;
  int ValueProfileMap_fd;
  int p_TORC8_fd;
  int p_TORC4_fd;
  int p_data_copy_fd;
  Modules=(fuzzer::TracePC::Module*)files_mapSharedMem(
          4096*sizeof(Module), &Modules_fd, "fuzzer modules");
  ValueProfileMap=(ValueBitMap*)files_mapSharedMem(
          sizeof(ValueBitMap), &ValueProfileMap_fd, "fuzzer ValueProfileMap");
  p_TORC8=(TableOfRecentCompares<uint64_t, 32>*)files_mapSharedMem(
          sizeof(TableOfRecentCompares<uint64_t, 32>), &p_TORC8_fd, "p_TORC8");
  p_TORC4=(TableOfRecentCompares<uint32_t, 32>*)files_mapSharedMem(
          sizeof(TableOfRecentCompares<uint32_t, 32>), &p_TORC4_fd, "p_TORC4");
  data_copy=(uint8_t *)files_mapSharedMem(
          0x100000, &p_data_copy_fd, "p_p_data_copy_fd");
  dup2(p_data_copy_fd, _HF_DATA_COPY_FD);
  dup2(Modules_fd, _HF_BITMAP_FD);
  dup2(ValueProfileMap_fd, _HF_VALUE_PROFILE_MAP_FD);
  dup2(p_TORC4_fd, _HF_TORC4_FD);
  dup2(p_TORC8_fd, _HF_TORC8_FD);
}


void TracePC::HandlePCsInit(const uintptr_t *Start, const uintptr_t *Stop) {
  const PCTableEntry *B = reinterpret_cast<const PCTableEntry *>(Start);
  const PCTableEntry *E = reinterpret_cast<const PCTableEntry *>(Stop);
  if (NumPCTables && ModulePCTable[NumPCTables - 1].Start == B) return;
  assert(NumPCTables < sizeof(ModulePCTable) / sizeof(ModulePCTable[0]));
  ModulePCTable[NumPCTables++] = {B, E};
  NumPCsInPCTables += E - B;
}

void TracePC::PrintModuleInfo() {
  if (NumModules) {
    Printf("INFO: Loaded %zd modules   (%zd inline 8-bit counters): ",
           NumModules, NumInline8bitCounters);
    for (size_t i = 0; i < NumModules; i++)
      Printf("%zd [%p, %p), ", Modules[i].Size(), Modules[i].Start(),
             Modules[i].Stop());
    Printf("\n");
  }
  if (NumPCTables) {
    Printf("INFO: Loaded %zd PC tables (%zd PCs): ", NumPCTables,
           NumPCsInPCTables);
    for (size_t i = 0; i < NumPCTables; i++) {
      Printf("%zd [%p,%p), ", ModulePCTable[i].Stop - ModulePCTable[i].Start,
             ModulePCTable[i].Start, ModulePCTable[i].Stop);
    }
    Printf("\n");

    if (NumInline8bitCounters && NumInline8bitCounters != NumPCsInPCTables) {
      Printf("ERROR: The size of coverage PC tables does not match the\n"
             "number of instrumented PCs. This might be a compiler bug,\n"
             "please contact the libFuzzer developers.\n"
             "Also check https://bugs.llvm.org/show_bug.cgi?id=34636\n"
             "for possible workarounds (tl;dr: don't use the old GNU ld)\n");
      _Exit(1);
    }
  }
  if (size_t NumExtraCounters = ExtraCountersEnd() - ExtraCountersBegin())
    Printf("INFO: %zd Extra Counters\n", NumExtraCounters);
}

ATTRIBUTE_NO_SANITIZE_ALL
void TracePC::HandleCallerCallee(uintptr_t Caller, uintptr_t Callee) {
  const uintptr_t kBits = 12;
  const uintptr_t kMask = (1 << kBits) - 1;
  uintptr_t Idx = (Caller & kMask) | ((Callee & kMask) << kBits);
  ValueProfileMap->AddValueModPrime(Idx);
}

/// \return the address of the previous instruction.
/// Note: the logic is copied from `sanitizer_common/sanitizer_stacktrace.h`
inline ALWAYS_INLINE uintptr_t GetPreviousInstructionPc(uintptr_t PC) {
#if defined(__arm__)
  // T32 (Thumb) branch instructions might be 16 or 32 bit long,
  // so we return (pc-2) in that case in order to be safe.
  // For A32 mode we return (pc-4) because all instructions are 32 bit long.
  return (PC - 3) & (~1);
#elif defined(__powerpc__) || defined(__powerpc64__) || defined(__aarch64__)
  // PCs are always 4 byte aligned.
  return PC - 4;
#elif defined(__sparc__) || defined(__mips__)
  return PC - 8;
#else
  return PC - 1;
#endif
}

/// \return the address of the next instruction.
/// Note: the logic is copied from `sanitizer_common/sanitizer_stacktrace.cpp`
ALWAYS_INLINE uintptr_t TracePC::GetNextInstructionPc(uintptr_t PC) {
#if defined(__mips__)
  return PC + 8;
#elif defined(__powerpc__) || defined(__sparc__) || defined(__arm__) || \
    defined(__aarch64__)
  return PC + 4;
#else
  return PC + 1;
#endif
}

void TracePC::UpdateObservedPCs() {
  Vector<uintptr_t> CoveredFuncs;
  auto ObservePC = [&](const PCTableEntry *TE) {
    if (ObservedPCs.insert(TE).second && DoPrintNewPCs) {
      PrintPC("\tNEW_PC: %p %F %L", "\tNEW_PC: %p",
              GetNextInstructionPc(TE->PC));
      Printf("\n");
    }
  };

  auto Observe = [&](const PCTableEntry *TE) {
    if (PcIsFuncEntry(TE))
      if (++ObservedFuncs[TE->PC] == 1 && NumPrintNewFuncs)
        CoveredFuncs.push_back(TE->PC);
    ObservePC(TE);
  };

  if (NumPCsInPCTables) {
    if (NumInline8bitCounters == NumPCsInPCTables) {
      for (size_t i = 0; i < NumModules; i++) {
        auto &M = Modules[i];
        assert(M.Size() ==
               (size_t)(ModulePCTable[i].Stop - ModulePCTable[i].Start));
        for (size_t r = 0; r < M.NumRegions; r++) {
          auto &R = M.Regions[r];
          if (!R.Enabled) continue;
          for (uint8_t *P = R.Start; P < R.Stop; P++)
            if (*P)
              Observe(&ModulePCTable[i].Start[M.Idx(P)]);
        }
      }
    }
  }

  for (size_t i = 0, N = Min(CoveredFuncs.size(), NumPrintNewFuncs); i < N;
       i++) {
    Printf("\tNEW_FUNC[%zd/%zd]: ", i + 1, CoveredFuncs.size());
    PrintPC("%p %F %L", "%p", GetNextInstructionPc(CoveredFuncs[i]));
    Printf("\n");
  }
}

uintptr_t TracePC::PCTableEntryIdx(const PCTableEntry *TE) {
  size_t TotalTEs = 0;
  for (size_t i = 0; i < NumPCTables; i++) {
    auto &M = ModulePCTable[i];
    if (TE >= M.Start && TE < M.Stop)
      return TotalTEs + TE - M.Start;
    TotalTEs += M.Stop - M.Start;
  }
  assert(0);
  return 0;
}

const TracePC::PCTableEntry *TracePC::PCTableEntryByIdx(uintptr_t Idx) {
  for (size_t i = 0; i < NumPCTables; i++) {
    auto &M = ModulePCTable[i];
    size_t Size = M.Stop - M.Start;
    if (Idx < Size) return &M.Start[Idx];
    Idx -= Size;
  }
  return nullptr;
}

static std::string GetModuleName(uintptr_t PC) {
  char ModulePathRaw[4096] = "";  // What's PATH_MAX in portable C++?
  void *OffsetRaw = nullptr;
  if (!EF->__sanitizer_get_module_and_offset_for_pc(
      reinterpret_cast<void *>(PC), ModulePathRaw,
      sizeof(ModulePathRaw), &OffsetRaw))
    return "";
  return ModulePathRaw;
}

template<class CallBack>
void TracePC::IterateCoveredFunctions(CallBack CB) {
  for (size_t i = 0; i < NumPCTables; i++) {
    auto &M = ModulePCTable[i];
    assert(M.Start < M.Stop);
    auto ModuleName = GetModuleName(M.Start->PC);
    for (auto NextFE = M.Start; NextFE < M.Stop; ) {
      auto FE = NextFE;
      assert(PcIsFuncEntry(FE) && "Not a function entry point");
      do {
        NextFE++;
      } while (NextFE < M.Stop && !(PcIsFuncEntry(NextFE)));
      CB(FE, NextFE, ObservedFuncs[FE->PC]);
    }
  }
}

void TracePC::SetFocusFunction(const std::string &FuncName) {
  // This function should be called once.
  assert(!FocusFunctionCounterPtr);
  if (FuncName.empty())
    return;
  for (size_t M = 0; M < NumModules; M++) {
    auto &PCTE = ModulePCTable[M];
    size_t N = PCTE.Stop - PCTE.Start;
    for (size_t I = 0; I < N; I++) {
      if (!(PcIsFuncEntry(&PCTE.Start[I]))) continue;  // not a function entry.
      auto Name = DescribePC("%F", GetNextInstructionPc(PCTE.Start[I].PC));
      if (Name[0] == 'i' && Name[1] == 'n' && Name[2] == ' ')
        Name = Name.substr(3, std::string::npos);
      if (FuncName != Name) continue;
      Printf("INFO: Focus function is set to '%s'\n", Name.c_str());
      FocusFunctionCounterPtr = Modules[M].Start() + I;
      return;
    }
  }
}

bool TracePC::ObservedFocusFunction() {
  return FocusFunctionCounterPtr && *FocusFunctionCounterPtr;
}

void TracePC::PrintCoverage() {
  if (!EF->__sanitizer_symbolize_pc ||
      !EF->__sanitizer_get_module_and_offset_for_pc) {
    Printf("INFO: __sanitizer_symbolize_pc or "
           "__sanitizer_get_module_and_offset_for_pc is not available,"
           " not printing coverage\n");
    return;
  }
  Printf("COVERAGE:\n");
  auto CoveredFunctionCallback = [&](const PCTableEntry *First,
                                     const PCTableEntry *Last,
                                     uintptr_t Counter) {
    assert(First < Last);
    auto VisualizePC = GetNextInstructionPc(First->PC);
    std::string FileStr = DescribePC("%s", VisualizePC);
    if (!IsInterestingCoverageFile(FileStr))
      return;
    std::string FunctionStr = DescribePC("%F", VisualizePC);
    if (FunctionStr.find("in ") == 0)
      FunctionStr = FunctionStr.substr(3);
    std::string LineStr = DescribePC("%l", VisualizePC);
    size_t NumEdges = Last - First;
    Vector<uintptr_t> UncoveredPCs;
    for (auto TE = First; TE < Last; TE++)
      if (!ObservedPCs.count(TE))
        UncoveredPCs.push_back(TE->PC);
    Printf("%sCOVERED_FUNC: hits: %zd", Counter ? "" : "UN", Counter);
    Printf(" edges: %zd/%zd", NumEdges - UncoveredPCs.size(), NumEdges);
    Printf(" %s %s:%s\n", FunctionStr.c_str(), FileStr.c_str(),
           LineStr.c_str());
    if (Counter)
      for (auto PC : UncoveredPCs)
        Printf("  UNCOVERED_PC: %s\n",
               DescribePC("%s:%l", GetNextInstructionPc(PC)).c_str());
  };

  IterateCoveredFunctions(CoveredFunctionCallback);
}

// Value profile.
// We keep track of various values that affect control flow.
// These values are inserted into a bit-set-based hash map.
// Every new bit in the map is treated as a new coverage.
//
// For memcmp/strcmp/etc the interesting value is the length of the common
// prefix of the parameters.
// For cmp instructions the interesting value is a XOR of the parameters.
// The interesting value is mixed up with the PC and is then added to the map.

ATTRIBUTE_NO_SANITIZE_ALL
void TracePC::AddValueForMemcmp(void *caller_pc, const void *s1, const void *s2,
                                size_t n, bool StopAtZero) {
  if (!n) return;
  size_t Len = std::min(n, Word::GetMaxSize());
  const uint8_t *A1 = reinterpret_cast<const uint8_t *>(s1);
  const uint8_t *A2 = reinterpret_cast<const uint8_t *>(s2);
  uint8_t B1[Word::kMaxSize];
  uint8_t B2[Word::kMaxSize];
  // Copy the data into locals in this non-msan-instrumented function
  // to avoid msan complaining further.
  size_t Hash = 0;  // Compute some simple hash of both strings.
  for (size_t i = 0; i < Len; i++) {
    B1[i] = A1[i];
    B2[i] = A2[i];
    size_t T = B1[i];
    Hash ^= (T << 8) | B2[i];
  }
  size_t I = 0;
  uint8_t HammingDistance = 0;
  for (; I < Len; I++) {
    if (B1[I] != B2[I] || (StopAtZero && B1[I] == 0)) {
      HammingDistance = Popcountll(B1[I] ^ B2[I]);
      break;
    }
  }
  size_t PC = reinterpret_cast<size_t>(caller_pc);
  size_t Idx = (PC & 4095) | (I << 12);
  Idx += HammingDistance;
  ValueProfileMap->AddValue(Idx);
  TORCW.Insert(Idx ^ Hash, Word(B1, Len), Word(B2, Len));
}

template <class T>
ATTRIBUTE_TARGET_POPCNT ALWAYS_INLINE
ATTRIBUTE_NO_SANITIZE_ALL
void TracePC::HandleCmp(uintptr_t PC, T Arg1, T Arg2) {
  uint64_t ArgXor = Arg1 ^ Arg2;
  if (sizeof(T) == 4)
      p_TORC4->Insert(ArgXor, Arg1, Arg2);
  else if (sizeof(T) == 8)
      p_TORC8->Insert(ArgXor, Arg1, Arg2);
  uint64_t HammingDistance = Popcountll(ArgXor);  // [0,64]
  uint64_t AbsoluteDistance = (Arg1 == Arg2 ? 0 : Clzll(Arg1 - Arg2) + 1);
  ValueProfileMap->AddValue(PC * 128 + HammingDistance);
  ValueProfileMap->AddValue(PC * 128 + 64 + AbsoluteDistance);
}

void TracePC::ClearInlineCounters() {
  IterateCounterRegions([](const Module::Region &R){
    if (R.Enabled)
      memset(R.Start, 0, R.Stop - R.Start);
  });
}

ATTRIBUTE_NO_SANITIZE_ALL
void TracePC::RecordInitialStack() {
  int stack;
  __sancov_lowest_stack = InitialStack = reinterpret_cast<uintptr_t>(&stack);
}

uintptr_t TracePC::GetMaxStackOffset() const {
  return InitialStack - __sancov_lowest_stack;  // Stack grows down
}

void WarnAboutDeprecatedInstrumentation(const char *flag) {
  // Use RawPrint because Printf cannot be used on Windows before OutputFile is
  // initialized.
  RawPrint(flag);
  RawPrint(
      " is no longer supported by libFuzzer.\n"
      "Please either migrate to a compiler that supports -fsanitize=fuzzer\n"
      "or use an older version of libFuzzer\n");
  exit(1);
}

} // namespace fuzzer