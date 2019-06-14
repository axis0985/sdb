#ifndef __SDB_H__
#define __SDB_H__
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>

typedef struct {
    short enabled;
    uint8_t data;
    pid_t pid;
    void* addr;
} breakpoint;

struct _sdb_t {
    pid_t p; // current load process
    char* p_name;
    breakpoint** breakpoints;
    int n_breakpoints;
    short r_state; // running state
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
void start();
void run();
void cont();
void si();

// for breakpoints
void breakp(char *addr);
void deletep(char *addr);
breakpoint* new_breakpoint(pid_t, void*);
void enable(breakpoint*);
void disable(breakpoint*);

//regs
uint64_t get_register_value(reg r);
void set_register_value(reg r,uint64_t val);
void set_reg(char* reg_name, char* v);
void get_reg(char* reg_name);

#endif