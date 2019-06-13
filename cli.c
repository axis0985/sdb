#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "cli.h"
#include "sdb.h"

void start_cli() {
    init();
    char *cmd =  malloc(MAX_PROMT*sizeof(char));
    while (1) {
        memset(cmd, 0,  MAX_PROMT*sizeof(char));
        printf("sdb> ");
        fgets(cmd, MAX_PROMT*sizeof(char), stdin);
        int cmd_idx ;
        for (cmd_idx = 0 ; *(cmd+cmd_idx) != ' ' && *(cmd+cmd_idx) != 0 && *(cmd+cmd_idx) != 10  ; cmd_idx++) ;
        if (cmd_idx == 0) continue;
        if (strncmp(cmd, "load", 4) == 0) {
            if ( 1< strlen(cmd+cmd_idx+1)) {
                int end ;
                for (end= 0 ; *(cmd+cmd_idx+end) != 10  ; end++);
                *(cmd+cmd_idx+end )= 0;
                load(cmd+(cmd_idx+1));
            } else {
                printf("too few argument\n");
            }
        } else if (strncmp(cmd, "q", 1) == 0 || strncmp(cmd, "exit", 4) == 0) {
            exit(0);
        }  else if (strncmp(cmd, "start", 5) == 0 ) {
            start();
        } else if (strncmp(cmd, "run", 3) == 0 || strncmp(cmd, "r", 1) == 0){
            run();
        }else if (strncmp(cmd, "cont", 4) == 0 || strncmp(cmd, "r", 1) == 0){
            run();
        } else if (strncmp(cmd, "pid", 3) == 0) {
            printf("child process = %d\n", sdb_t.p);
        } else {
            continue;
        }
        //puts(cmd);
    }
}

