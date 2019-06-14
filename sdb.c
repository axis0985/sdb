#include "sdb.h"
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/user.h>

void errquit(const char *msg) {
    perror(msg);
    exit(-1);
}

void init() {
    sdb_t.p = -1;
    sdb_t.breakpoints = NULL;
    sdb_t.n_breakpoints = 0;
    sdb_t.r_state = 0;
}

void load(char *program) {
    char *tmp = malloc(64*sizeof(char));
    strcpy(tmp, program);
    sdb_t.p_name = tmp;
    printf("** program \'%s\' loaded\n", sdb_t.p_name);
}

void start() {
    // free breakpoints
    int i;
    for (i =0; i < sdb_t.n_breakpoints; i++) free(sdb_t.breakpoints[i]);
    sdb_t.breakpoints = NULL;
    sdb_t.n_breakpoints = 0;
    //
    pid_t pid ;
    if ((pid = fork()) <0 ) errquit("fork");
    if(pid == 0) {
        //child
        if (ptrace(PTRACE_TRACEME) < 0) errquit("ptrace");
        execl(sdb_t.p_name, "", NULL);
        errquit("execl");
    } else {
        int status;
        if (waitpid(pid, &status, 0) < 0) errquit("waitpid");
        ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);
        ptrace(PTRACE_SINGLESTEP);
        waitpid(pid, &status, 0);
        if(WIFSTOPPED(status) == 0) {
            printf("Something went south\n");
        }
        if (pid >0) {
            sdb_t.p = pid; 
            sdb_t.r_state = 0;
            printf("** pid %d\n", sdb_t.p);
        }
    }
}

void run() {
    if (sdb_t.r_state == 1) {
        fprintf(stderr, "Already running\n");
        return;
    }
    int status;
    if (sdb_t.p <0 ) {
        fprintf(stderr, "Start before run\n");
        return;
    }
    sdb_t.r_state = 1;
    ptrace(PTRACE_CONT,sdb_t.p,0,0);
    waitpid(sdb_t.p, &status, 0);
    if (WIFSTOPPED(status)) {
        uint64_t loc = get_register_value(rip)-1;
        int i ;
        for (i = 0; i < sdb_t.n_breakpoints; i++) {
            if (sdb_t.breakpoints[i]->addr == (void*)loc) {
                fprintf(stderr, "** breakpoint @ %lx\n",  get_register_value(rip)-1);
            }
        }
    }
}

void cont() {
    if (sdb_t.r_state == 0) {
        fprintf(stderr, "Start first\n");
        return;
    }
    int status;
    if (sdb_t.p <0 ) {
        fprintf(stderr, "Start before cont\n");
        return;
    }
    uint64_t loc = get_register_value(rip)-1;
    int i ;
    for (i = 0; i < sdb_t.n_breakpoints; i++) {
        if (sdb_t.breakpoints[i]->addr == (void*)loc) {

            breakpoint* b = sdb_t.breakpoints[i];
            
            if (b->enabled) {
                set_register_value(rip, loc);

                disable(b);
                ptrace(PTRACE_SINGLESTEP, sdb_t.p, NULL, 0);
                waitpid(sdb_t.p, &status,0);
                enable(b);
            }
        }
    }
    ptrace(PTRACE_CONT, sdb_t.p, 0, 0);
    waitpid(sdb_t.p, &status, 0);
    if (WIFSTOPPED(status)) {
        uint64_t loc = get_register_value(rip)-1;
        int i ;
        for (i = 0; i < sdb_t.n_breakpoints; i++) {
            if (sdb_t.breakpoints[i]->addr == (void*)loc) {
                fprintf(stderr, "** breakpoint @ %lx\n", get_register_value(rip)-1);
            }
        }
    }
}

void si() {
    int status;
    if (sdb_t.p <0 ) {
        fprintf(stderr, "Start before cont\n");
        return;
    }
    ptrace(PTRACE_SINGLESTEP, sdb_t.p, 0 ,0);
    waitpid(sdb_t.p, &status, 0);
}

//for breakpoints
void breakp(char *args) {
    void* addr = (void*)strtol(args, NULL, 16);
    breakpoint* b = new_breakpoint(sdb_t.p,  addr);
    enable(b);
    sdb_t.breakpoints = realloc(sdb_t.breakpoints, (++sdb_t.n_breakpoints)*sizeof(breakpoint*));
    sdb_t.breakpoints[sdb_t.n_breakpoints-1] = b;
}

void deletep(char *args) {
    void* addr = (void*)strtol(args, NULL, 16);
}

breakpoint* new_breakpoint(pid_t pid, void* addr) {
  breakpoint* b = malloc(sizeof(breakpoint));
  b->pid = pid;
  b->addr = addr;
  b->enabled = 0;
  b->data = 0;
  return b;
}

void enable(breakpoint* b) {
    long data = ptrace(PTRACE_PEEKDATA, b->pid, b->addr, 0);
    b->data = data & 0xff;
    uint64_t int3 = 0xcc;
    uint64_t data_with_int3 = ((data & ~0xff) | int3);
    ptrace(PTRACE_POKEDATA, b->pid, b->addr, data_with_int3);

    b->enabled = 1;
}

void disable(breakpoint* b) {
    long data = ptrace(PTRACE_PEEKDATA, b->pid, b->addr, 0);
    long restored = ((data & ~0xff) | b->data);
    ptrace(PTRACE_POKEDATA, b->pid, b->addr, restored);

    b->enabled = 0;
}

//regs
typedef struct {
    reg r;
    int dwarf_r;
    const char name[10];
} reg_descriptor;

int n_registers = 27;

const reg_descriptor reg_descriptors[27] = {
    { r15, 15, "r15" },
    { r14, 14, "r14" },
    { r13, 13, "r13" },
    { r12, 12, "r12" },
    { rbp, 6, "rbp" },
    { rbx, 3, "rbx" },
    { r11, 11, "r11" },
    { r10, 10, "r10" },
    { r9, 9, "r9" },
    { r8, 8, "r8" },
    { rax, 0, "rax" },
    { rcx, 2, "rcx" },
    { rdx, 1, "rdx" },
    { rsi, 4, "rsi" },
    { rdi, 5, "rdi" },
    { orig_rax, -1, "orig_rax" },
    { rip, -1, "rip" },
    { cs, 51, "cs" },
    { rflags, 49, "eflags" },
    { rsp, 7, "rsp" },
    { ss, 52, "ss" },
    { fs_base, 58, "fs_base" },
    { gs_base, 59, "gs_base" },
    { ds, 53, "ds" },
    { es, 50, "es" },
    { fs, 54, "fs" },
    { gs, 55, "gs" },
};

const reg_descriptor* get_register_from_name(const char* name) {
    int i;

    for (i = 0; i < n_registers; i++) {
      if (!strcmp(name, reg_descriptors[i].name)) return &reg_descriptors[i];
    }

    return NULL;
}

uint64_t get_register_value(reg r) {
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, sdb_t.p , NULL, &regs);

    switch (r) {
      case rax: return regs.rax;
      case rbx: return regs.rbx;
      case rcx: return regs.rcx;
      case rdx: return regs.rdx;
      case rdi: return regs.rdi;
      case rsi: return regs.rsi;
      case rbp: return regs.rbp;
      case rsp: return regs.rsp;
      case r8: return regs.r8;
      case r9: return regs.r9;
      case r10: return regs.r10;
      case r11: return regs.r11;
      case r12: return regs.r12;
      case r13: return regs.r13;
      case r14: return regs.r14;
      case r15: return regs.r15;
      case rip: return regs.rip;
      case eflags: return regs.eflags;
      case cs: return regs.cs;
      case orig_rax: return regs.orig_rax;
      case fs_base: return regs.fs_base;
      case gs_base: return regs.gs_base;
      case fs: return regs.fs;
      case gs: return regs.gs;
      case ss: return regs.ss;
      case ds: return regs.ds;
      case es: return regs.es;
      default: return 0;
    }
}
void set_register_value(reg r, uint64_t val) {
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, sdb_t.p , NULL, &regs);

    switch (r) {
      case rax:
        regs.rax = val;
        break;
      case rbx:
        regs.rbx = val;
        break;
      case rcx:
        regs.rcx = val;
        break;
      case rdx:
        regs.rdx = val;
        break;
      case rdi:
        regs.rdi = val;
        break;
      case rsi:
        regs.rsi = val;
        break;
      case rbp:
        regs.rbp = val;
        break;
      case rsp:
        regs.rsp = val;
        break;
      case r8:
        regs.r8 = val;
        break;
      case r9:
        regs.r9 = val;
        break;
      case r10:
        regs.r10 = val;
        break;
      case r11:
        regs.r11 = val;
        break;
      case r12:
        regs.r12 = val;
        break;
      case r13:
        regs.r13 = val;
        break;
      case r14:
        regs.r14 = val;
        break;
      case r15:
        regs.r15 = val;
        break;
      case rip:
        regs.rip = val;
        break;
      case eflags:
        regs.eflags = val;
        break;
      case cs:
        regs.cs = val;
        break;
      case orig_rax:
        regs.orig_rax = val;
        break;
      case fs_base:
        regs.fs_base = val;
        break;
      case gs_base:
        regs.gs_base = val;
        break;
      case fs:
        regs.fs = val;
        break;
      case gs:
        regs.gs = val;
        break;
      case ss:
        regs.ss = val;
        break;
      case ds:
        regs.ds = val;
        break;
      case es:
        regs.es = val;
        break;
      default: break;
    }
    ptrace(PTRACE_SETREGS, sdb_t.p, NULL, &regs);
}

void set_reg(char* reg_name, char* v) {
    uint64_t val;
    if (strncmp(v, "0x", 2) == 0)
        val = strtol(v,NULL,16);
    else
        val = atol(v);
    reg r = get_register_from_name(reg_name)->r;
    //printf("%s %ld\n",v,  val);
    set_register_value(r, val);
}

void get_reg(char* reg_name) {
    reg r = get_register_from_name(reg_name)->r;
    uint64_t val = get_register_value(r);
    fprintf(stderr, "%s = %ld(0x%lx)\n", reg_name, val, val);
}
