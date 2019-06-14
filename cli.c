#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "cli.h"
#include "sdb.h"

#define _CMD *(cmd+cmd_idx)
#define _ARG *(cmd+cmd_idx+arg_idx)
#define CMD_ARG cmd+cmd_idx+arg_start

void start_cli() {
    init();
    char *cmd =  malloc(MAX_PROMT*sizeof(char));
    while (1) {
        memset(cmd, 0,  MAX_PROMT*sizeof(char));
        printf("sdb> ");
        fgets(cmd, MAX_PROMT*sizeof(char), stdin);
        
        //fucking string process
        int cmd_idx, arg_idx, arg_start ;
        for (cmd_idx = 0 ; _CMD!= ' ' && _CMD != 0 && _CMD != 10  ; cmd_idx++) ;
        for (arg_idx = 0 ; _ARG == ' ' && (arg_idx + cmd_idx) < MAX_PROMT; arg_idx++) ;
        arg_start = arg_idx;
        for (; _ARG != 0 && _ARG != 10; arg_idx++) ;
        _ARG = 0;


        if (cmd_idx == 0) continue;
        if (strncmp(cmd, "load", 4) == 0) {
            if ( arg_start != arg_idx) {
                load(CMD_ARG);
            } else {
                printf("too few argument\n");
            }
        } else if (strncmp(cmd, "break", 5) == 0 || strncmp(cmd, "b", 1) == 0 ) {
            if ( arg_start != arg_idx) {
                breakp(CMD_ARG);
            } else {
                printf("too few argument\n");
            }
        } else  if (strncmp(cmd, "get", 3) == 0) {
            if ( arg_start != arg_idx) {
                get_reg(CMD_ARG);
            } else {
                printf("too few argument\n");
            }
        } else if (strncmp(cmd, "set", 3) == 0 ) {
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
        } else if (strncmp(cmd, "q", 1) == 0 || strncmp(cmd, "exit", 4) == 0) {
            exit(0);
        }  else if (strncmp(cmd, "start", 5) == 0 ) {
            start();
        } else if (strncmp(cmd, "run", 3) == 0 || strncmp(cmd, "r", 1) == 0){
            run();
        }else if (strncmp(cmd, "cont", 4) == 0 || strncmp(cmd, "c", 1) == 0){
            cont();
        } else if (strncmp(cmd, "si", 2) == 0) {
            si();
        } else if (strncmp(cmd, "pid", 3) == 0) {
            printf("child process = %d\n", sdb_t.p);
        } else {
            continue;
        }
        //puts(cmd);
    }
}

