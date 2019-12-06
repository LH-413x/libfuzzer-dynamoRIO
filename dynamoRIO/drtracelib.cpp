//
// Created by alex on 2019/11/22.
//

#include "dr_api.h"
#include "drmgr.h"
#include "drx.h"
#include "drcovlib.h"
#include <string.h>
#include <drwrap.h>


#include <iostream>
#include <unordered_map>
#include <mutex>

#include <instrument.h>
#include <sys/mman.h>

std::mutex trace_mutex;
std::unordered_map<std::string, size_t> modules_map;
bool should_trace=false;
const char* black_list_modules[]={
        "libInst.so",
        "libc.so",
        "libstdc++",
        "ld-elf",
        "ld-linux",
        "ld-2.5",
        "libdl.so",
        "libpthread.so",
        "librt.so",
        "linux-vdso.so",
        "liblz4",
        "liblzma.so",
        "libgcc",
};
#define NUM_BLACK_ITEM sizeof(black_list_modules) / sizeof(black_list_modules[0])
#define ATTRIBUTE_ALIGNED(X) __attribute__((aligned(X)))

struct ValueBitMap {
    static const size_t kMapSizeInBits = 1 << 16;
    static const size_t kMapPrimeMod = 65371;  // Largest Prime < kMapSizeInBits;
    static const size_t kBitsInWord = (sizeof(uintptr_t) * 8);
    static const size_t kMapSizeInWords = kMapSizeInBits / kBitsInWord;
public:

    // Clears all bits.
    void Reset() { memset(Map, 0, sizeof(Map)); }

    // Computes a hash function of Value and sets the corresponding bit.
    // Returns true if the bit was changed from 0 to 1.
    inline bool AddValue(uintptr_t Value) {
      uintptr_t Idx = Value % kMapSizeInBits;
      uintptr_t WordIdx = Idx / kBitsInWord;
      uintptr_t BitIdx = Idx % kBitsInWord;
      uintptr_t Old = Map[WordIdx];
      uintptr_t New = Old | (1ULL << BitIdx);
      Map[WordIdx] = New;
      return New != Old;
    }

    inline bool AddValueModPrime(uintptr_t Value) {
      return AddValue(Value % kMapPrimeMod);
    }

    inline bool Get(uintptr_t Idx) {
      uintptr_t WordIdx = Idx / kBitsInWord;
      uintptr_t BitIdx = Idx % kBitsInWord;
      return Map[WordIdx] & (1ULL << BitIdx);
    }

    size_t SizeInBits() const { return kMapSizeInBits; }

    template <class Callback>
    void ForEach(Callback CB) const {
      for (size_t i = 0; i < kMapSizeInWords; i++)
        if (uintptr_t M = Map[i])
          for (size_t j = 0; j < sizeof(M) * 8; j++)
            if (M & ((uintptr_t)1 << j))
              CB(i * sizeof(M) * 8 + j);
    }

private:
    ATTRIBUTE_ALIGNED(512) uintptr_t Map[kMapSizeInWords];
};

struct Module {
  struct Region {
    uint8_t *Start, *Stop;
    bool Enabled;
    bool OneFullPage;
  };
  Region Regions[0x1000];
  size_t NumRegions;
  uint8_t *Start() { return Regions[0].Start; }
  uint8_t *Stop()  { return Regions[NumRegions - 1].Stop; }
  size_t Size()   { return Stop() - Start(); }
  size_t  Idx(uint8_t *P) {
    return P - Start();
  }
};

#define _HF_BITMAP_FD 1023
#define _HF_VALUE_PROFILE_MAP_FD 1000
#define _HF_TORC8_FD 1001
#define _HF_TORC4_FD 1002

Module* modules;

template<class T, size_t kSizeT>
struct TableOfRecentCompares {
  static const size_t kSize = kSizeT;
  struct Pair {
    T A, B;
  };
  void Insert(size_t Idx, const T &Arg1, const T &Arg2) {
    Idx = Idx % kSize;
    Table[Idx].A = Arg1;
    Table[Idx].B = Arg2;
  }

  Pair Get(size_t I) { return Table[I % kSize]; }
  Pair Table[kSize];
};

TableOfRecentCompares<uint32_t, 32>* p_TORC4;
TableOfRecentCompares<uint64_t, 32>* p_TORC8;
ValueBitMap* p_ValueBitMap;

void* get_shared_map(int fd, size_t sz){
  return mmap(NULL, 4096*sizeof(Module),
       PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_SHARED ,fd,0);
}

void init_fuzzer_trace(){
  modules=(Module*)get_shared_map(_HF_BITMAP_FD, 4096*sizeof(Module));
  p_ValueBitMap=(ValueBitMap*)get_shared_map(_HF_VALUE_PROFILE_MAP_FD, sizeof(ValueBitMap));
  p_TORC4=(TableOfRecentCompares<uint32_t, 32>*)get_shared_map(_HF_TORC4_FD,
          sizeof(TableOfRecentCompares<uint32_t, 32>));
  p_TORC8=(TableOfRecentCompares<uint64_t, 32>*)get_shared_map(_HF_TORC8_FD,
          sizeof(TableOfRecentCompares<uint64_t, 32>));
  if(modules==MAP_FAILED || p_ValueBitMap==MAP_FAILED || p_TORC4==MAP_FAILED || p_TORC4==MAP_FAILED){
    exit(0);
  }
}

static dr_emit_flags_t
event_basic_block_analysis(void *drcontext, void *tag, instrlist_t *bb, bool for_trace,
                           bool translating, OUT void **user_data){
    if(should_trace==false){
        return DR_EMIT_DEFAULT;
    }
    module_data_t *mod = dr_lookup_module(dr_fragment_app_pc(tag));
    if(mod != nullptr){
        if(modules_map.count(dr_module_preferred_name(mod))==0){
            dr_free_module_data(mod);
            return DR_EMIT_DEFAULT;
        }
        dr_free_module_data(mod);
    }
    instr_t *instr;
    auto instr_is_cmp=[](instr_t* instr,opnd_t* opnd_first, opnd_t* opnd_second){
        int opc = instr_get_opcode(instr);
        if(opc==OP_cmp){
            *opnd_first=instr_get_src(instr,0);
            *opnd_second=instr_get_src(instr, 1);
            std::cout << "second: " << opnd_second->black_box_uint64 << std::endl;
            return true;
        }
        return false;
    };
    //if_hfuzz_trace_pc_internal((uintptr_t)instr_get_app_pc(instrlist_first(bb)));

    for (instr = instrlist_first(bb); instr != NULL; instr = instr_get_next(instr)){
        opnd_t opnd_first;
        opnd_t opnd_second;
        if(instr_is_cmp(instr, &opnd_first, &opnd_second)){
           // __sanitizer_cov_trace_cmp1(0,opnd.black_box_uint);
           //std::cout << "cmp" <<std::endl;
          size_t PC=(size_t)instr_get_app_pc(instr);
          //std::cout << "instr_get_app_pc" <<std::endl;
          if(p_ValueBitMap->AddValue(opnd_second.black_box_uint64)){
            std::cout << "update" << std::endl;
          }
          std::cout << "p_ValueBitMap->AddValue: " << opnd_second.black_box_uint64 <<std::endl;
          uint64_t ArgXor = opnd_first.black_box_uint ^ opnd_second.black_box_uint64;
          p_TORC4->Insert(ArgXor, opnd_first.black_box_uint,opnd_second.black_box_uint64);
          //std::cout << "p_TORC4" <<std::endl;
          p_TORC8->Insert(ArgXor, opnd_first.black_box_uint,opnd_second.black_box_uint64);
        }
    }
}

static void
event_module_load(void *drcontext, const module_data_t *info, bool loaded) {
    //std::cout << "load module: " << dr_module_preferred_name(info) << std::endl;

    std::string name(dr_module_preferred_name(info));
    //black list some module
    for(auto bn : black_list_modules){
        if(name.find(bn) != std::string::npos){
            return;
        }
    }
    //check main module

    modules_map[name]=(size_t)info->start;
    std::cout << "load module: " << dr_module_preferred_name(info) << std::endl;

    if(should_trace==true){
        return;
    }

    app_pc interface = (app_pc)dr_get_proc_address(info->handle, "LLVMFuzzerTestOneInput");

    //need to build the project with -rdynamic, or locate interface will fail
    // its global symbols will be present in .dynsym
    if(interface == nullptr){
        interface = (app_pc)dr_get_proc_address(info->handle, "main");
    }
    if(interface){
        std::cout << "do find main" << std::endl;
        auto wrap_pre_interface=[](void *wrapcxt, OUT void **user_data){
            should_trace=true;
        };
        auto wrap_post_interface=[](void *wrapcxt, void *user_data){
            should_trace=false;
        };
        drwrap_wrap(interface, wrap_pre_interface, wrap_post_interface);
    }
}

#include <unistd.h>

drcovlib_status_t drtracelib_init() {
    dr_set_client_name("drtracelib", "");
    drmgr_init();
    drx_init();
    drwrap_init();
    init_fuzzer_trace();
    //constrain interface
    drmgr_register_module_load_event(event_module_load);
    //drmgr_register_module_unload_event(event_module_unload);
    drmgr_register_bb_instrumentation_event(event_basic_block_analysis, NULL, NULL);
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[]){
    drtracelib_init();
}