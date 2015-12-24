#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <elf.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <errno.h>
#include <link.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <time.h>
#include <signal.h>
#include <sys/user.h>
#include <sys/prctl.h>

#if defined(DEBUG) && DEBUG > 0
 #define DEBUG_PRINT(fmt, args...) _printf("DEBUG: %s:%d:%s(): " fmt, \
    __FILE__, __LINE__, __func__, ##args)
#else
 #define DEBUG_PRINT(fmt, args...) /* Don't do anything in release builds */
#endif

#define PAGE_ALIGN(x) (x & ~(PAGE_SIZE - 1))
#define PAGE_ALIGN_UP(x) (PAGE_ALIGN(x) + PAGE_SIZE) 
#define PAGE_ROUND(x) (PAGE_ALIGN_UP(x))
#define STACK_SIZE 0x4000000
/*
 * We pass these to sys_clone
 * for our create_thread() function
 */
#define CLONE_UNTRACED 0x00800000 
#define SIGCHLD         17
#define CLONE_VM        0x00000100      /* set if VM shared between processes */
#define CLONE_FS        0x00000200      /* set if fs info shared between processes */
#define CLONE_FILES     0x00000400      /* set if open files shared between processes */
#define CLONE_SIGHAND   0x00000800      /* set if signal handlers shared */

struct linux_dirent64 {
        uint64_t             d_ino;
        int64_t             d_off;
        unsigned short  d_reclen;
        unsigned char   d_type;
        char            d_name[0];
} __attribute__((packed));



unsigned long get_rip(void);
int _fstat(long, void *);
long _lseek(long, long, unsigned int);
void Exit(long);
void *_mmap(void *, unsigned long, unsigned long, unsigned long,  long, unsigned long);
long _open(const char *, unsigned long);
long _write(long, char *, unsigned long);
int _read(long, char *, unsigned long);
long _ptrace(long, long, void *, void *);
int _wait4(long, long *, long, long *);
void _pause(void);
int _clone(unsigned long, unsigned long, unsigned int, long);
int _getpid(void);
int _getppid(void);
long _kill(unsigned int, unsigned int);
int _sigaction(unsigned int, struct sigaction *, struct sigaction *);
int _gettimeofday(void *, void *);
void exit_thread(void);
int _getdents64(unsigned int fd, struct linux_dirent64 *dirp,
                    unsigned int count);

int create_thread(void (*)(void *), void *);
void _memcpy(void *, void *, unsigned int);
char * _fgets(char *, size_t, int, long *);
int _sprintf(char *, char *fmt, ...);
int _printf(char *, ...);
char * itoa(long, char *);
char * itox(long, char *);
int _puts(char *);
size_t _strlen(char *);
char *_strchr(const char *, int);
char * _strrchr(const char *, int);
int _strncmp(const char *, const char *, size_t);
int _strcmp(const char *, const char *);
int _memcmp(const void *, const void *, unsigned int);


#define MALLOC(len) heap_alloc(len)
#define FREE(ptr) heap_free(ptr)


void * heap_alloc(unsigned int);
void heap_free(void *);
int _nanosleep(struct timespec *req, struct timespec *rem);
