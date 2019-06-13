#ifndef __SDB_H__
#define __SDB_H__
#include <stdio.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>

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

#endif