#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "cli.h"
#include "sdb.h"

#define _CMD *(cmd+cmd_idx)
#define _ARG *(cmd+cmd_idx+arg_idx)
#define CMD_ARG cmd+cmd_idx+arg_start

void start_cli(char* load_program) {
    init();
    char *cmd =  malloc(MAX_PROMT*sizeof(char));
    char * command = malloc(MAX_PROMT*sizeof(char));
    if (strcmp(load_program, "") != 0) {
        load(load_program); 
    }
    while (1) {
        memset(cmd, 0,  MAX_PROMT*sizeof(char));
        memset(command, 0,  MAX_PROMT*sizeof(char));
        printf("sdb> ");
        fgets(cmd, MAX_PROMT*sizeof(char), stdin);
        
        //fucking string process
        
        int cmd_start, cmd_idx, arg_idx, arg_start ;
        for (cmd_idx = 0 ; _CMD == ' ' ; cmd_idx++) ;
        cmd_start = cmd_idx;
        for (cmd_idx; _CMD!= ' ' && _CMD != 0 && _CMD != 10  ; cmd_idx++) ;
        strncpy(command,  cmd+cmd_start, cmd_idx-cmd_start);
        for (arg_idx = 0 ; _ARG == ' ' && (arg_idx + cmd_idx) < MAX_PROMT; arg_idx++) ;
        arg_start = arg_idx;
        for (; _ARG != 0 && _ARG != 10; arg_idx++) ;
        _ARG = 0;

        if (cmd_idx == 0) continue;
        if (strcmp(command, "load") == 0) {
            if ( arg_start != arg_idx) {
                load(CMD_ARG);
            } else {
                printf("too few argument\n");
            }
        } else if (strcmp(command, "delete") == 0) {
            if ( arg_start != arg_idx) {
                int arg = atoi(CMD_ARG);
                delete_breakpoint(arg);
            } else {
                printf("too few argument\n");
            }
        } else if (strcmp(command, "break") == 0 || strcmp(command, "b") == 0 ) {
            if ( arg_start != arg_idx) {
                breakp(CMD_ARG);
            } else {
                printf("too few argument\n");
            }
        } else  if (strcmp(command, "get") == 0|| strcmp(command, "g") == 0 ) {
            if ( arg_start != arg_idx) {
                get_reg(CMD_ARG);
            } else {
                printf("too few argument\n");
            }
        } else  if (strcmp(command, "dump") == 0|| strcmp(command, "x") == 0 ) {
            if ( arg_start != arg_idx) {
                dump(CMD_ARG);
            } else {
                printf("too few argument\n");
            }
        } else  if (strcmp(command, "disasm") == 0|| strcmp(command, "d") == 0 ) {
            if ( arg_start != arg_idx) {
                disasm(CMD_ARG);
            } else {
                if (sdb_t.cur_disasm_addr == -1) {
                    printf("** no addr is given\n");
                } else {
                    disasm("");
                }
            }
        } else if (strcmp(command, "set") == 0 || strcmp(command, "s") == 0 ) {
            if ( arg_start != arg_idx) {
                char *args[2];
                int i; //third args start
                for (i=0; i < 2 ;i++ ) 
                    args [i] = malloc(32*sizeof(char));
                for (i =0 ; *(cmd+cmd_idx+arg_start+i) !=' ' && (cmd_idx + arg_start + i ) < MAX_PROMT; i++);
                strncpy(args[0], cmd+cmd_idx+arg_start, i);
                for (; *(cmd+cmd_idx+arg_start+i) == ' ' && (cmd_idx + arg_start + i ) < MAX_PROMT; i++);
                strcpy(args[1], cmd+cmd_idx+arg_start+i);
                set_reg(args[0], args[1]);
            } else {
                printf("too few argument\n");
            }
        } else if (strcmp(command, "vmmap") == 0 || strcmp(command, "m") == 0 ) {
            vmmap();
        } else if (strcmp(command, "list") == 0 || strcmp(command, "l") == 0 ) {
            list_breakpoints();
        } else if (strcmp(command, "getregs") == 0  ) {
            get_all_regs();
        } else if (strcmp(command, "help") == 0 || strcmp(command, "h") == 0  ) {
            fprintf(stderr, "- break {instruction-address}: add a break point\n" \
"- cont: continue execution\n" \
"- delete {break-point-id}: remove a break point\n" \
"- disasm addr: disassemble instructions in a file or a memory region\n" \
"- dump addr [length]: dump memory content\n" \
"- exit: terminate the debugger\n" \
"- get reg: get a single value from a register\n" \
"- getregs: show registers\n" \
"- help: show this message\n" \
"- list: list break points\n" \
"- load {path/to/a/program}: load a program\n" \
"- run: run the program\n" \
"- vmmap: show memory layout\n" \
"- set reg val: get a single value to a register\n" \
"- si: step into instruction\n" \
"- start: start the program and stop at the first instruction\n");
        } else if (strcmp(command, "q") == 0 || strcmp(command, "exit") == 0) {
            exit(0);
        }  else if (strcmp(command, "start") == 0 ) {
            start(1);
        } else if (strcmp(command, "run") == 0 || strcmp(command, "r") == 0){
            run();
        }else if (strcmp(command, "cont") == 0 || strcmp(command, "c") == 0){
            cont();
        } else if (strcmp(command, "si") == 0) {
            si();
        } else if (strcmp(command, "pid") == 0) {
            printf("child process = %d\n", sdb_t.p);
        } else {
            continue;
        }
        //puts(cmd);
    }
}

