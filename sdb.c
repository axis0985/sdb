#include "sdb.h"
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <sys/wait.h>

void errquit(const char *msg) {
    perror(msg);
    exit(-1);
}

void init() {
    sdb_t.p = -1;
}

void load(char *program) {
    char *tmp = malloc(64*sizeof(char));
    strcpy(tmp, program);
    sdb_t.p_name = tmp;
    printf("** program \'%s\' loaded\n", sdb_t.p_name);
}

void start() {
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
            printf("** pid %d\n", sdb_t.p);
        }
    }
}

void run() {
    int status;
    if (sdb_t.p <0 ) {
        fprintf(stderr, "Start before run\n");
        return;
    }
    ptrace(PTRACE_CONT,sdb_t.p,0,0);
    waitpid(sdb_t.p, &status, 0);
}

void cont() {
    int status;
    if (sdb_t.p <0 ) {
        fprintf(stderr, "Start before cont\n");
        return;
    }
    ptrace(PTRACE_CONT, sdb_t.p, 0, 0);
    waitpid(sdb_t.p, &status, 0);
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