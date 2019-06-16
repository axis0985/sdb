#ifndef __SDB_H__
#define __SDB_H__
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <capstone/capstone.h>
#include "elftool.h"

#define PEEKSIZE 8

typedef struct {
    short enabled;
    uint8_t data;
    pid_t pid;
    void* addr;
} breakpoint;

struct  {
    pid_t p; // current load process
    char* p_name;
    breakpoint** breakpoints;
    int n_breakpoints;
    short r_state; // running state
    elf_handle_t *eh;
    elf_strtab_t *tab;
    long long text_addr;
    long long text_offset;
    long long text_size;
    long long cur_disasm_addr; //current disasm address
    long long text_base_addr; // base address for PIE
    int text_index;
} sdb_t;

typedef enum {
  rax,
  rbx,
  rcx,
  rdx,
  rdi,
  rsi,
  rbp,
  rsp,
  r8,
  r9,
  r10,
  r11,
  r12,
  r13,
  r14,
  r15,
  rip,
  rflags,
  cs,
  orig_rax,
  fs_base,
  gs_base,
  fs,
  gs,
  ss,
  ds,
  es,
  eflags,
} reg;

void errquit(const char *msg);
void init();
void load(char *program);
void start(short should_print);
void run();
void cont();
void si();
void vmmap();
void dump(char *addr);

// capstone related
void disasm(char* addr);

// for breakpoints
void breakp(char *addr);
breakpoint* new_breakpoint(pid_t, void*);
void enable(breakpoint*);
void disable(breakpoint*);
void list_breakpoints();
void delete_breakpoint(int idx);

//regs
uint64_t get_register_value(reg r);
void set_register_value(reg r,uint64_t val);
void set_reg(char* reg_name, char* v);
void get_reg(char* reg_name);
void get_all_regs();

#endif