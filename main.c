#include "cli.h"

int main(int argc, char *argv[]) {
    if (argc >1) {
        start_cli(argv[1]);
    } else {
        start_cli("");
    }
    return 0;
}