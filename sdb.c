#include "sdb.h"
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <sys/user.h>
#include <signal.h>

void errquit(const char *msg) {
    perror(msg);
    exit(-1);
}

void init() {
    sdb_t.p = -1;
    sdb_t.breakpoints = NULL;
    sdb_t.n_breakpoints = 0;
    sdb_t.r_state = 0;
    sdb_t.eh = NULL;
    sdb_t.tab = NULL;
    sdb_t.text_addr = 0;
    sdb_t.text_offset = 0;
    sdb_t.text_size = 0;
    sdb_t.cur_disasm_addr =-1;
    sdb_t.text_base_addr = 0;
    elf_init();
}

void load(char *program) {
    if ((sdb_t.eh = elf_open(program)) == NULL) {
		fprintf(stderr, "** unable to open '%s'.\n", program);
		return;
    }

    if(elf_load_all(sdb_t.eh) < 0) {
		fprintf(stderr, "** unable to load '%s.\n", program);
		return;
	}

    for(sdb_t.tab = sdb_t.eh->strtab; sdb_t.tab != NULL; sdb_t.tab = sdb_t.tab->next) {
		if(sdb_t.tab->id == sdb_t.eh->shstrndx) break;
	}

    if(sdb_t.tab == NULL) {
		fprintf(stderr, "** section header string table not found.\n");
        return;
	}
    int i;
    for(i = 0; i < sdb_t.eh->shnum; i++) {
        if (strcmp(&sdb_t.tab->data[sdb_t.eh->shdr[i].name], ".text") == 0) {
            sdb_t.text_addr = sdb_t.eh->shdr[i].addr;
            sdb_t.text_offset = sdb_t.eh->shdr[i].offset;
            sdb_t.text_size = sdb_t.eh->shdr[i].size;
        }
	}

    char *tmp = malloc(64*sizeof(char));
    strcpy(tmp, program);
    sdb_t.p_name = tmp;
    
    // free breakpoints
    for (i =0; i < sdb_t.n_breakpoints; i++) free(sdb_t.breakpoints[i]);
    sdb_t.breakpoints = NULL;
    sdb_t.n_breakpoints = 0;
    
    printf("** program \'%s\' loaded. entry point 0x%llx, vaddr 0x%llx, offset 0x%llx, size 0x%llx\n", 
        sdb_t.p_name,
        sdb_t.text_addr,
        sdb_t.text_addr,
        sdb_t.text_offset,
        sdb_t.text_size);
}

void start(short should_print) {
    // TODO: restart breakpoints reload
    // 
    if (sdb_t.p >0 ) {
        int status;
        kill(sdb_t.p, SIGKILL);
        waitpid(sdb_t.p, &status, 0);
        sdb_t.p = -1;
        elf_close(sdb_t.eh);
        sdb_t.eh = NULL;
    }
    sdb_t.text_base_addr = 0;
    pid_t pid ;
    if ((pid = fork()) <0 ) errquit("fork");
    if(pid == 0) {
        //child
        int status;
        if (ptrace(PTRACE_TRACEME) < 0) errquit("ptrace");
        execl(sdb_t.p_name, "", NULL);
        errquit("execl");
    } else {
        int status;
        if (waitpid(pid, &status, 0) < 0) errquit("waitpid");
        ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);
        // ptrace(PTRACE_SINGLESTEP);
        // waitpid(pid, &status, 0);
        // if(WIFSTOPPED(status) == 0) {
        //     printf("Something went south\n");
        // }
        if (pid >0) {
            sdb_t.p = pid; 
            sdb_t.r_state = 0;

            //get base address
            FILE *fp;
            char process_map[128] = "";
            sprintf(process_map, "/proc/%d/maps", sdb_t.p);
            fp = fopen(process_map, "r");
            char addr[40];
            fscanf(fp, "%[^-]s %*[^\n]s",addr);
            fclose(fp);
            sdb_t.text_base_addr = strtol(addr, NULL, 16);

            // breakpoints enable
            int i;
            for (i= 0 ; i<sdb_t.n_breakpoints;i++) {
                sdb_t.breakpoints[i]->pid = sdb_t.p;
                sdb_t.breakpoints[i]->addr = sdb_t.breakpoints[i]->addr + sdb_t.text_base_addr;
                fprintf(stderr,"%p\n", sdb_t.breakpoints[i]->addr);
                enable(sdb_t.breakpoints[i]);
            }

            if (should_print ==1)
                fprintf(stderr, "** pid %d\n", sdb_t.p);
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
    if (WIFEXITED(status)) {
        sdb_t.p =  -1;
        fprintf(stderr, "** child process %d terminated normally (code 0)\n", sdb_t.p);
    }
}

void cont() {
    if (sdb_t.r_state == 0) {
        fprintf(stderr, "Run first\n");
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
    if (WIFEXITED(status)) {
        sdb_t.p = -1;
        fprintf(stderr, "** child process %d terminated normally (code 0)\n", sdb_t.p);
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

void vmmap() {
    if (sdb_t.p < 0) {
        fprintf(stderr, "%016llx-%016llx %3s %llx %s\n",sdb_t.text_addr, sdb_t.text_addr+sdb_t.text_size,  "r-x",  sdb_t.text_offset, sdb_t.p_name);
        return;
    }
    FILE *fp;
    char process_map[128] = "";
    sprintf(process_map, "/proc/%d/maps", sdb_t.p);
    fp = fopen(process_map, "r");
    char addr[40];
    char mode[8];
    char mname[128];
    int offset;
    while(fscanf(fp, "%s %s %d %*s %[^\n]s %*[^\n]", addr ,mode,&offset, mname) == 4) {
        int i;
        for (i = 0 ; addr[i] != '-' ; i++ ) ;
        char s_addr[20];
        char e_addr[20];
        memset(s_addr, '0', sizeof(s_addr));
        memset(e_addr, '0', sizeof(e_addr));
        strncpy(s_addr+(16-i), addr, i);
        strncpy(e_addr+(16-i), addr+i+1, i);
        s_addr[16] = '\0';
        e_addr[16] = '\0';
        for (i = 0; mname[i] != ' '; i++);
        for (; mname[i] == ' '; i++);
        fprintf(stderr, "%s-%s %3s %d %s\n",s_addr, e_addr,  mode,  offset, mname+i);
    }
    fclose(fp);
}

void dump(char * addr) {
    void* _addr = (void*)strtol(addr, NULL, 16);
    int i; 
    char dump_code[40] ;
    for (i = 0 ; i < 10 ; i ++) {
        long ret = ptrace(PTRACE_PEEKDATA, sdb_t.p, _addr, NULL);
        if (i % 2 ==0 ) {
            memset(dump_code, 0 , sizeof(dump_code));
            fprintf(stderr, "%p: ", _addr);
        }
        // fprintf(stderr, "%016lx", ret);
        int j;
        for (j = 0 ; j < 8 ; j ++) {
            long tmp = 0xffffffffffffffff;
            tmp = tmp << (8);
            tmp = 0xffffffffffffffff ^ tmp;
            tmp = tmp & ret >> (j*8);
            // tmp = tmp & ret;
            // tmp = ret & tmp;
            fprintf(stderr, "%2.2lx ", tmp);
            if  (tmp >=32 && tmp <= 126)
                dump_code[ (i%2)*8+j ] = (int) tmp;
            else
                dump_code[ (i%2)*8+j ] = '.';
        }
        _addr += 8;
        if (i % 2 ==1 )
            fprintf(stderr, "|%s|\n", dump_code);
    }
}

// capstone related
void disasm(char* addr) {
    csh handle;
    cs_insn  *insn;
    char buf[64] = {0};
    size_t count;
    unsigned long long target_addr;
    unsigned long long ptr;

    if (sdb_t.p < 0) {
        // no running process
        start(0);
    }

    if (strcmp(addr, "") != 0) {
        if (strncmp(addr, "0x", 2) == 0)
            target_addr = strtol(addr,NULL,16);
        else
            target_addr = atol(addr);
    } else {
        target_addr = sdb_t.cur_disasm_addr;
    }
    if (sdb_t.text_addr == sdb_t.text_offset) //PIE?
        target_addr += (unsigned long long ) sdb_t.text_base_addr;
    ptr = target_addr;
    
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK ) {
        fprintf(stderr, "Unable to start capstone\n");
        return;
    }

    for(ptr =  target_addr; ptr <  target_addr + sizeof(buf); ptr += PEEKSIZE) {
        long long peek;
        peek = ptrace(PTRACE_PEEKTEXT, sdb_t.p, ptr, NULL);
        memcpy(&buf[ptr- target_addr], &peek, PEEKSIZE);
    }
    if((count = cs_disasm(handle, (uint8_t*) buf, target_addr-ptr, target_addr, 0, &insn)) > 0) {
        size_t j;
        for (j = 0; j < count && j < 10; j++ ) {
            if (insn[j].address >= sdb_t.text_base_addr + sdb_t.text_offset+sdb_t.text_size ||
                insn[j].address < sdb_t.text_base_addr + sdb_t.text_offset) break;
            int i;
            if (sdb_t.text_addr == sdb_t.text_offset) //PIE?
                fprintf(stderr, "  %llx :", insn[j].address- sdb_t.text_base_addr);
            else
                fprintf(stderr, "  %lx :", insn[j].address);

            for (i = 0; i < insn[j].size; i++) {
                fprintf(stderr, "%2.2x ",insn[j].bytes[i]);
            }
            fprintf(stderr, " \t%s\t%s\n", insn[j].mnemonic, insn[j].op_str);
        }

        sdb_t.cur_disasm_addr = insn[j].address-sdb_t.text_base_addr;
        cs_free(insn, count);
    }
    cs_close(&handle);
}

//for breakpoints
void breakp(char *args) {
    void* addr = (void*)strtol(args, NULL, 16);
    breakpoint* b = new_breakpoint(sdb_t.p,  addr);
    if(sdb_t.p >0)
        enable(b);
    sdb_t.breakpoints = realloc(sdb_t.breakpoints, (++sdb_t.n_breakpoints)*sizeof(breakpoint*));
    sdb_t.breakpoints[sdb_t.n_breakpoints-1] = b;
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

void list_breakpoints() {
    int i ;
    for (i = 0; i < sdb_t.n_breakpoints; i++) {
        fprintf(stderr, "%d: %p \n",i,sdb_t.breakpoints[i]->addr); 
    }
}

void delete_breakpoint(int idx) {
    if (idx >= sdb_t.n_breakpoints--) {
        fprintf(stderr, "Delete what?\n");
        return;
    }
    disable(sdb_t.breakpoints[idx]);
    free(sdb_t.breakpoints[idx]);
    int i;
    for (i= idx ; i<sdb_t.n_breakpoints;i++) {
        sdb_t.breakpoints[i] = sdb_t.breakpoints[i+1];
    }
}

//regs
typedef struct {
    reg r;
    int dwarf_r;
    const char name[10];
} reg_descriptor;

int n_registers = 27;

const reg_descriptor reg_descriptors[27] = {
    { rax, 0, "RAX" },
    { rbx, 3, "RBX" },
    { rcx, 2, "RCX" },
    { rdx, 1, "RDX" },
    { r8, 8, "R8" },
    { r9, 9, "R9" },
    { r10, 10, "R10" },
    { r11, 11, "R11" },
    { r12, 12, "R12" },
    { r13, 13, "R13" },
    { r14, 14, "R14" },
    { r15, 15, "R15" },
    { rdi, 5, "RDI" },
    { rsi, 4, "RSI" },
    { rbp, 6, "RBP" },
    { rsp, 7, "RSP" },
    { rip, -1, "RIP" },
    { eflags, 49, "FLAGS" },
    { orig_rax, -1, "orig_rax" },
    { cs, 51, "cs" },
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

void get_all_regs() {
    int i;
    for (i = 0 ; i < 18; i++ ) {
        uint64_t val = get_register_value(reg_descriptors[i].r);
        if (i == 17)
            fprintf(stderr, "%s  %016lx\t", reg_descriptors[i].name,    val);
        else
            fprintf(stderr, "%s  %lx\t", reg_descriptors[i].name,    val);
        if(i %4 == 3) 
            fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");
}