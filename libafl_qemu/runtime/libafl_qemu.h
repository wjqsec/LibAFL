#ifndef LIBAFL_QEMU_H
#define LIBAFL_QEMU_H

/**
 * LibAFL QEMU header file.
 *
 * This file is a portable header file used to build target harnesses more
 * conveniently. Its main purpose is to generate ready-to-use calls to
 * communicate with the fuzzer. The list of commands is available at the bottom
 * of this file. The rest mostly consists of macros generating the code used by
 * the commands.
 */

/* === The private part starts here === */

/* This part should not be useful for most people. Callable commands are
 * available at the end of this file. */

#define STRINGIFY(s) #s
#define XSTRINGIFY(s) STRINGIFY(s)

// Target Specific imports / definitions
#ifdef _WIN32
  #include <stdint.h>
  #include <intsafe.h>

typedef UINT64 libafl_word;
  #define LIBAFL_CALLING_CONVENTION __fastcall

#else
  #include <stdint.h>

  #if defined(__x86_64__) || defined(__aarch64__)
    typedef uint64_t libafl_word;
    #define LIBAFL_CALLING_CONVENTION __attribute__(())
  #endif

  #ifdef __arm__
    typedef uint32_t libafl_word;
    #define LIBAFL_CALLING_CONVENTION __attribute__(())
  #endif
#endif

#define LIBAFL_SYNC_EXIT_OPCODE 0x66f23a0f
#define LIBAFL_BACKDOOR_OPCODE 0x44f23a0f

#define LIBAFL_QEMU_HDR_VERSION_NUMBER 0111  // TODO: find a nice way to set it.

typedef enum LibaflQemuCommand {
  LIBAFL_QEMU_COMMAND_START_VIRT = 0,
  LIBAFL_QEMU_COMMAND_START_PHYS = 1,
  LIBAFL_QEMU_COMMAND_INPUT_VIRT = 2,
  LIBAFL_QEMU_COMMAND_INPUT_PHYS = 3,
  LIBAFL_QEMU_COMMAND_END = 4,
  LIBAFL_QEMU_COMMAND_SAVE = 5,
  LIBAFL_QEMU_COMMAND_LOAD = 6,
  LIBAFL_QEMU_COMMAND_VERSION = 7,
  LIBAFL_QEMU_COMMAND_VADDR_FILTER_ALLOW = 8,

  
  LIBAFL_QEMU_COMMAND_SMM_REPORT_DUMMY_MEM = 11,
  LIBAFL_QEMU_COMMAND_SMM_INIT_ENTER = 12,
  LIBAFL_QEMU_COMMAND_SMM_INIT_EXIT = 13,
  LIBAFL_QEMU_COMMAND_SMM_SMI_ENTER = 14,
  LIBAFL_QEMU_COMMAND_SMM_SMI_EXIT = 15,
  LIBAFL_QEMU_COMMAND_SMM_REPORT_SMI_SELECT_INFO = 16,
  LIBAFL_QEMU_COMMAND_SMM_REPORT_COMMBUF_INFO = 17,
  LIBAFL_QEMU_COMMAND_SMM_GET_SMI_SELECT_FUZZ_DATA = 18,
  LIBAFL_QEMU_COMMAND_SMM_GET_COMMBUF_FUZZ_DATA = 19,
  
} LibaflExit;

typedef enum LibaflQemuEndStatus {
  LIBAFL_QEMU_END_UNKNOWN = 0,
  LIBAFL_QEMU_END_OK = 1,
  LIBAFL_QEMU_END_CRASH = 2,

  LIBAFL_QEMU_END_SMM_INIT_START = 3,
  LIBAFL_QEMU_END_SMM_INIT_END = 4,
  LIBAFL_QEMU_END_SMM_MODULE_START = 5,
  LIBAFL_QEMU_END_SMM_FUZZ_START = 6,
  LIBAFL_QEMU_END_SMM_FUZZ_END = 7, 
} LibaflExitEndParams;

#ifdef _WIN32
    #define LIBAFL_DEFINE_FUNCTIONS(name, _opcode) \
      #ifdef __cplusplus \
        extern "C" { \
      #endif \
          static __attribute__((unused,noinline)) libafl_word LIBAFL_CALLING_CONVENTION _libafl_##name##_call0(libafl_word action); \
          static __attribute__((unused,noinline)) libafl_word LIBAFL_CALLING_CONVENTION _libafl_##name##_call1(libafl_word action, \
                                                        ##name##  libafl_word arg1); \
          static __attribute__((unused,noinline)) libafl_word LIBAFL_CALLING_CONVENTION _libafl_##name##_call2(libafl_word action, \
                                                                   libafl_word arg1, \
                                                                   libafl_word arg2); \
      #ifdef __cplusplus \
        } \
      #endif
#else

  #if defined(__x86_64__)
    #define LIBAFL_DEFINE_FUNCTIONS(name, opcode)                                                   \
      static __attribute__((unused,noinline)) libafl_word LIBAFL_CALLING_CONVENTION _libafl_##name##_call0(                                 \
          libafl_word action) {                                                                     \
        libafl_word ret;                                                                            \
        __asm__ volatile (                                                                        \
              "mov %1, %%rax\n"                                                                   \
              ".4byte " XSTRINGIFY(opcode) "\n"                                                   \
              "mov %%rax, %0\n"                                                                   \
              : "=g"(ret)                                                                         \
              : "g"(action)                                                                       \
              : "%rax"                                                                            \
          ); \
        return ret;                                                                                 \
      }                                                                                             \
                                                                                                    \
      static __attribute__((unused,noinline)) libafl_word LIBAFL_CALLING_CONVENTION _libafl_##name##_call1(                                 \
          libafl_word action, libafl_word arg1) {                                                   \
        libafl_word ret;                                                                            \
        __asm__ volatile (                                                                        \
            "mov %1, %%rax\n"                                                                     \
            "mov %2, %%rdi\n"                                                                     \
            ".4byte " XSTRINGIFY(opcode) "\n"                                                     \
            "mov %%rax, %0\n"                                                                     \
            : "=g"(ret)                                                                           \
            : "g"(action), "g"(arg1)                                                              \
            : "%rax", "%rdi"                                                                      \
            ); \
        return ret;                                                                                 \
      }                                                                                             \
                                                                                                    \
       static __attribute__((unused,noinline)) libafl_word LIBAFL_CALLING_CONVENTION _libafl_##name##_call2(                                 \
          libafl_word action, libafl_word arg1, libafl_word arg2) {                                 \
        libafl_word ret;                                                                            \
        __asm__ volatile (                                                                        \
        "mov %1, %%rax\n"                                                                         \
        "mov %2, %%rdi\n"                                                                         \
        "mov %3, %%rsi\n"                                                                         \
        ".4byte " XSTRINGIFY(opcode) "\n"                                                         \
        "mov %%rax, %0\n"                                                                         \
        : "=g"(ret)                                                                               \
        : "g"(action), "g"(arg1), "g"(arg2)                                                       \
        : "%rax", "%rdi", "%rsi"                                                                  \
        ); \
        return ret;                                                                                 \
      }                                                                                             \
       static __attribute__((unused,noinline)) libafl_word LIBAFL_CALLING_CONVENTION _libafl_##name##_call3(                                 \
          libafl_word action, libafl_word arg1, libafl_word arg2,libafl_word arg3) {                 \
        libafl_word ret;                                                                            \
        __asm__ volatile (                                                                        \
        "mov %1, %%rax\n"                                                                         \
        "mov %2, %%rdi\n"                                                                         \
        "mov %3, %%rsi\n"                                                                         \
        "mov %4, %%rdx\n"                                                                         \
        ".4byte " XSTRINGIFY(opcode) "\n"                                                         \
        "mov %%rax, %0\n"                                                                         \
        : "=g"(ret)                                                                               \
        : "g"(action), "g"(arg1), "g"(arg2), "g"(arg3)                                            \
        : "%rax", "%rdi", "%rsi"                                                                  \
        );                                                                                          \
        return ret;                                                                                 \
      }                                                                                           
        
  #elif defined(__arm__)
    #define LIBAFL_DEFINE_FUNCTIONS(name, opcode)                                                   \
      static __attribute__((unused,noinline)) libafl_word LIBAFL_CALLING_CONVENTION _libafl_##name##_call0(                                 \
          libafl_word action) {                                                                     \
        libafl_word ret;                                                                            \
        __asm__ volatile (                                                                        \
        "mov r0, %1\n"                                                                            \
        ".word " XSTRINGIFY(opcode) "\n"                                              \
        "mov %0, r0\n"                                                                            \
        : "=r"(ret)                                                                               \
        : "r"(action)                                                                             \
        : "r0"                                                                                    \
    ); \
        return ret;                                                                                 \
      }                                                                                             \
                                                                                                    \
      static __attribute__((unused,noinline)) libafl_word LIBAFL_CALLING_CONVENTION _libafl_##name##_call1(                                 \
          libafl_word action, libafl_word arg1) {                                                   \
        libafl_word ret;                                                                            \
        __asm__ volatile (                                                                      \
        "mov r0, %1\n"                                                                      \
        "mov r1, %2\n"                                                                      \
        ".word " XSTRINGIFY(opcode) "\n"                                        \
        "mov %0, r0\n"                                                                      \
        : "=r"(ret)                                                                         \
        : "r"(action), "r"(arg1)                                                            \
        : "r0", "r1"                                                                        \
    );   \
        return ret;                                                                                 \
      }                                                                                             \
                                                                                                    \
      static __attribute__((unused,noinline)) libafl_word LIBAFL_CALLING_CONVENTION _libafl_##name##_call2(                                 \
          libafl_word action, libafl_word arg1, libafl_word arg2) {                                 \
        libafl_word ret;                                                                            \
        __asm__ volatile (                                                                      \
        "mov r0, %1\n"                                                                      \
        "mov r1, %2\n"                                                                      \
        "mov r2, %3\n"                                                                      \
        ".word " XSTRINGIFY(opcode) "\n"                                        \
        "mov %0, r0\n"                                                                      \
        : "=r"(ret)                                                                         \
        : "r"(action), "r"(arg1), "r"(arg2)                                                 \
        : "r0", "r1", "r2"                                                                  \
    );   \
        return ret;                                                                                 \
      }

  #elif defined(__aarch64__)
    #define LIBAFL_DEFINE_FUNCTIONS(name, opcode)                                                   \
      static __attribute__((unused,noinline)) libafl_word LIBAFL_CALLING_CONVENTION _libafl_##name##_call0(                                 \
          libafl_word action) {                                                                     \
        libafl_word ret;                                                                            \
        __asm__ volatile (                                                                        \
        "mov x0, %1\n"                                                                            \
        ".word " XSTRINGIFY(opcode) "\n"                                              \
        "mov %0, x0\n"                                                                            \
        : "=r"(ret)                                                                               \
        : "r"(action)                                                                             \
        : "x0"                                                                                    \
    ); \
        return ret;                                                                                 \
      }                                                                                             \
                                                                                                    \
      static __attribute__((unused,noinline)) libafl_word LIBAFL_CALLING_CONVENTION _libafl_##name##_call1(                                 \
          libafl_word action, libafl_word arg1) {                                                   \
        libafl_word ret;                                                                            \
        __asm__ volatile (                                                                      \
        "mov x0, %1\n"                                                                      \
        "mov x1, %2\n"                                                                      \
        ".word " XSTRINGIFY(opcode) "\n"                                        \
        "mov %0, x0\n"                                                                      \
        : "=r"(ret)                                                                         \
        : "r"(action), "r"(arg1)                                                            \
        : "x0", "x1"                                                                        \
    );   \
        return ret;                                                                                 \
      }                                                                                             \
                                                                                                    \
      static __attribute__((unused,noinline)) libafl_word LIBAFL_CALLING_CONVENTION _libafl_##name##_call2(                                 \
          libafl_word action, libafl_word arg1, libafl_word arg2) {                                 \
        libafl_word ret;                                                                            \
        __asm__ volatile (                                                                      \
        "mov x0, %1\n"                                                                      \
        "mov x1, %2\n"                                                                      \
        "mov x2, %3\n"                                                                      \
        ".word " XSTRINGIFY(opcode) "\n"                                        \
        "mov %0, x0\n"                                                                      \
        : "=r"(ret)                                                                         \
        : "r"(action), "r"(arg1), "r"(arg2)                                                 \
        : "x0", "x1", "x2"                                                                  \
    );   \
        return ret;                                                                                 \
      }
  #else
    #warning "LibAFL QEMU Runtime does not support your architecture yet, please leave an issue."
  #endif

#endif

// Generates sync exit functions
LIBAFL_DEFINE_FUNCTIONS(sync_exit, LIBAFL_SYNC_EXIT_OPCODE)

// Generates backdoor functions
LIBAFL_DEFINE_FUNCTIONS(backdoor, LIBAFL_BACKDOOR_OPCODE)

/* === The private part ends here === */

/* === The public part starts here === */

/* LibAFL QEMU Commands */

#define LIBAFL_QEMU_START_VIRT(buf_vaddr, max_len) \
  _libafl_sync_exit_call2(LIBAFL_QEMU_COMMAND_START_VIRT, buf_vaddr, max_len)

#define LIBAFL_QEMU_START_PHYS(buf_paddr, max_len) \
  _libafl_sync_exit_call2(LIBAFL_QEMU_COMMAND_START_PHYS, buf_paddr, max_len)

#define LIBAFL_QEMU_INPUT_VIRT(buf_vaddr, max_len) \
  _libafl_sync_exit_call2(LIBAFL_QEMU_COMMAND_INPUT_VIRT, buf_vaddr, max_len)

#define LIBAFL_QEMU_INPUT_PHYS(buf_paddr, max_len) \
  _libafl_sync_exit_call2(LIBAFL_QEMU_COMMAND_INPUT_PHYS, buf_paddr, max_len)

#define LIBAFL_QEMU_SAVE() _libafl_sync_exit_call0(LIBAFL_QEMU_COMMAND_SAVE)

#define LIBAFL_QEMU_LOAD() _libafl_sync_exit_call0(LIBAFL_QEMU_COMMAND_LOAD) 

#define LIBAFL_QEMU_VERSION() _libafl_sync_exit_call0(LIBAFL_QEMU_COMMAND_VERSION)


//used by smm fuzz
#define LIBAFL_QEMU_END(status) _libafl_sync_exit_call1(LIBAFL_QEMU_COMMAND_END, status)
#define LIBAFL_QEMU_SMM_REPORT_DUMMY_MEM(addr) _libafl_backdoor_call1(LIBAFL_QEMU_COMMAND_SMM_REPORT_DUMMY_MEM,addr)
#define LIBAFL_QEMU_SMM_INIT_ENTER() _libafl_backdoor_call0(LIBAFL_QEMU_COMMAND_SMM_INIT_ENTER)
#define LIBAFL_QEMU_SMM_INIT_EXIT() _libafl_backdoor_call0(LIBAFL_QEMU_COMMAND_SMM_INIT_EXIT)
#define LIBAFL_QEMU_SMM_SMI_ENTER() _libafl_backdoor_call0(LIBAFL_QEMU_COMMAND_SMM_SMI_ENTER)
#define LIBAFL_QEMU_SMM_SMI_EXIT() _libafl_backdoor_call0(LIBAFL_QEMU_COMMAND_SMM_SMI_EXIT)


#define LIBAFL_QEMU_SMM_REPORT_SMI_SELECT_INFO(addr,size) _libafl_backdoor_call2(LIBAFL_QEMU_COMMAND_SMM_REPORT_SMI_SELECT_INFO,addr,size)
#define LIBAFL_QEMU_SMM_REPORT_COMMBUF_INFO(addr,size) _libafl_backdoor_call2(LIBAFL_QEMU_COMMAND_SMM_REPORT_COMMBUF_INFO,addr,size)
#define LIBAFL_QEMU_SMM_GET_SMI_SELECT_FUZZ_DATA() _libafl_backdoor_call0(LIBAFL_QEMU_COMMAND_SMM_GET_SMI_SELECT_FUZZ_DATA)
#define LIBAFL_QEMU_SMM_GET_COMMBUF_FUZZ_DATA(smi_index, fuzz_times) _libafl_backdoor_call2(LIBAFL_QEMU_COMMAND_SMM_GET_COMMBUF_FUZZ_DATA,smi_index, fuzz_times)
/* === The public part ends here === */

#endif
