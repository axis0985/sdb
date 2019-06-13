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
} sdb_t;

void errquit(const char *msg);
void init();
void load(char *program);
void start();
void run();
void cont();
void si();

// for breakpoints
breakpoint* new_breakpoint(pid_t, void*);
void enable(breakpoint*);
void disable(breakpoint*);

#endif