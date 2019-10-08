#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/memfd.h>
#include <sys/syscall.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <elf.h>
#include <stdint.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>
#include <stdint.h>
#include <sys/ptrace.h>  
#include <sys/types.h>  
#include <sys/wait.h>  
#include <unistd.h>  
/*#include <linux/user.h>   [> For constants , ORIG_EAX etc <]  */


static char *misc_arg = "THIS_IS_NOT_REAL_ARG";


int proc_child(const char *path, char *argv[], char *const envp[]) {
/*int proc_child(const char *path, char *argv[]) {*/
    int i = 0;
    int fd=0;
    int filesize=0;
    void *elfbuf = NULL;
    int mfd = 0;
    int res = 0;
    int nRead=0, nWrite = 0;
    char cmdline[256];
    int ret = 0;

    ptrace(PTRACE_TRACEME, 0, NULL, NULL); // wait to be ptraced

    printf("Child is Traced!\n");

    for(i=1; argv[i] != NULL; i++) {
        argv[i] = misc_arg;
    }

    /////// 
    fd = open(path, O_RDONLY);
    if(fd<0) {
        printf("open %s failed!\n", path);
        return -1;
    }

    filesize = lseek(fd, 0, SEEK_END);
    if(filesize <= 0) {
        printf("filesize = %d, error\n", filesize);
        return -1;
    }
    printf("filesize = %d\n", filesize);

    // reset file point
	lseek(fd, 0, SEEK_SET);
    // read file to elfbuf
    elfbuf = malloc(filesize);
    nRead = read(fd, elfbuf, filesize);
    close(fd);
    printf("nRead = %d filesize=%d\n", nRead, filesize);

    mfd = syscall(__NR_memfd_create, "elf", MFD_CLOEXEC);
    if(mfd < 0) {
        free(elfbuf);
        printf("memfd_create failed!");
        return -1;
    }

    if(ftruncate(mfd, filesize) != 0) {
        free(elfbuf);
        printf("ftruncate failed!");
        return -1;
    }

    nWrite = write(mfd, elfbuf, filesize);
    printf("mfd=%d, nWrite=%d\n", mfd, nWrite);
    free(elfbuf); elfbuf=NULL;

    sprintf(cmdline, "/proc/self/fd/%d", mfd);
    printf("cmdline: %s\n", cmdline);

    argv[0] = cmdline;

    ret = execve(argv[0], argv, envp);
    printf("child execve failed: ret=%d, err=%s\n", ret, strerror(errno));

    return 0;
}

uint64_t elfentry(const char *path)
{
    Elf64_Ehdr ehdr;
    int fd;
    
    fd = open(path, O_RDONLY);
    if(fd<0){
        return 0;
    }
    read(fd, (void*)&ehdr, sizeof(ehdr));
    close(fd);
    return ehdr.e_entry;
}

int m_execve(const char *path, char *argv[], char *envp[])
{
    pid_t   child = 0;
    int     status = 0;
    struct  user_regs_struct regs;
    long    addr = 0, argaddr = 0;
    union {
        long val;
        char chars[sizeof(long)];
    } data;
    int     arc = 0;
    int     i=0;

    uint64_t entry = elfentry(argv[0]);
    printf("argv[0]: %s, entry: 0x%lx\n", argv[0], entry);

    child = fork();
    if(child == -1){
        printf("fork failed!\n");
        return -1;
    }

    if(child == 0) {
        // child proc
        /*proc_child(argv[0], envp);*/
        proc_child(path, argv, envp);
        return 0;
    }

    // parent
    printf("child pid = %d\n", child);
    while(1) {
        /*printf("wait child!\n");*/
        wait(&status);
        if(WIFEXITED(status)){
            printf("status = %d\n", WEXITSTATUS(status));
            printf("normal exit!\n");
            break;
        }

        /*printf("trace.\n");*/
        ptrace(PTRACE_GETREGS, child, NULL, &regs);
        /*printf("regs.rip = 0x%llx\n", regs.rip);*/

        if(regs.rip == entry) {
            // stack 
            printf("EIP: _start %llx \n", regs.rip);
            printf("RSP: %llx \n", regs.rsp);

            addr = regs.rsp;

            // stack:
            // rsp:         argc
            // rsp+8:       argv ---->  argv[0]
            //                          argv[1] ---> "-al"
            //                          argv[2] ---> "/home/ubuntu/"
            //                          (argaddr)

            // 读取参数个数
            arc = ptrace(PTRACE_PEEKTEXT, child, addr, NULL);
            printf("argc = %d\n", arc);

            addr += 8;


            // 解析修改参数 
            for(i=1;i<arc;i++){
                argaddr = ptrace(PTRACE_PEEKTEXT, child, addr + (i*sizeof(void*)), NULL);
                char *tmpstr = argv[i];
                int offset = 0;
                int tmplen = strlen(tmpstr);

                printf("[+] argv[%d] = %s, %d\n", i, tmpstr, strlen(tmpstr));

                for(offset=0; offset<=tmplen; offset += sizeof(long)) {
                    data.val = ptrace(PTRACE_PEEKTEXT, child, argaddr, NULL);

                    printf("[*] PEEK: %s\n", data.chars);
                    strncpy(data.chars, tmpstr, sizeof(long));

                    ptrace(PTRACE_POKETEXT, child, argaddr, data.val);
                    printf("[*] POKE: %s\n", data.chars);

                    tmpstr += sizeof(long);
                    argaddr += sizeof(long);
                }
            }

            ptrace(PTRACE_CONT, child, NULL, NULL);
            ptrace(PTRACE_DETACH, child, NULL, NULL);

            break;
        }
        ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);
    }
    
    return 0;
}




int main() {
    char *argv[] = {"/bin/ls", "-al", "/home/ubuntu/", NULL};

    m_execve(argv[0], argv, NULL);

    return 0;
}
