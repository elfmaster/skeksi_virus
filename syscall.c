/*
 * Copyright (c) 2015, Ryan O'Neill
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer. 
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "private.h"

int _fsync(int fd)
{
        long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov $74, %%rax\n"
                        "syscall" : : "g"(fd));

        asm ("mov %%rax, %0" : "=r"(ret));
        return (int)ret;
}

int _gettimeofday(void *tv, void *tz)
{
	unsigned long ret;
	__asm__ volatile(
			"mov %0, %%rdi\n"
			"mov %1, %%rsi\n"
			"mov $96, %%rax\n"
			"syscall" : : "g"(tv), "g"(tz));
	return (int)ret;
}

int _sigaction(unsigned int sig, struct sigaction *act, struct sigaction *oldact)
{
	unsigned long ret;
	__asm__ volatile(
			"mov %0, %%rdi\n"
			"mov %1, %%rsi\n"
			"mov %2, %%rdx\n"
			"mov $13, %%rax\n"
			"syscall" : : "g"(sig), "g"(act), "g"(oldact));
	asm("mov %%rax, %0" : "=r"(ret));
	return (int)ret;

}

long _lseek(long fd, long offset, unsigned int whence)
{
        long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov %2, %%rdx\n"
                        "mov $8, %%rax\n"
                        "syscall" : : "g"(fd), "g"(offset), "g"(whence));
        asm("mov %%rax, %0" : "=r"(ret));
        return ret;

}

int _getpid(void)
{
        long ret;
        __asm__ volatile(
                        "mov $39, %%rax\n"
                        "syscall\n"
                        "mov %%rax, %0" : "=g"(ret));
        return (int)ret;
}

int _getppid(void)
{
	long ret;
	__asm__ volatile(
			"mov $110, %%rax\n"
			"syscall\n" 
			"mov %%rax, %0" : "=g"(ret));
	return (int)ret;
}
	
void _pause(void)
{
	__asm__ volatile(
			"mov $34, %rax\n"
			"syscall");

}

int _wait4(long pid, long *ptr, long options, long *usage)
{
	long ret;
	__asm__ volatile(
			"mov %0, %%rdi\n"
			"mov %1, %%rsi\n"
			"mov %2, %%rdx\n"
			"mov %3, %%r10\n"
			"mov $61, %%rax\n"
			"syscall" : : "g"(pid), "g"(ptr), "g"(options), "g"(usage));
	asm("mov %%rax, %0" : "=r"(ret));
	return (int) ret;

}

/*
 * Notice the (uint64_t) casts in the register constraints
 * if we don't have these, then we can't compile this code
 * with optimization because it tries to use 32bit registers
 * and fails to compile saying that mov is an illegal instruction.
 * this is a good lesson to note since I chased this for an hour.
 */
int _clone(unsigned long entry, unsigned long stack, unsigned int flags, long fd)
{
	long ret;
	__asm__ volatile(
			"mov %0, %%rdi\n"
			"mov %1, %%rsi\n"
			"mov %2, %%rdx\n"
			"mov %3, %%r10\n"
			"mov $56, %%rax\n" 
			"syscall\n"  ::  "g"((uint64_t)entry), "g"((uint64_t)stack), "g"((uint64_t)flags), "g"((uint64_t)fd));

	asm("mov %%rax, %0" : "=r"(ret));
	return (int)ret;
}

int _prctl(long option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
	long ret;
	
	__asm__ volatile(
			"mov %0, %%rdi\n"
			"mov %1, %%rsi\n"
			"mov %2, %%rdx\n"
			"mov %3, %%r10\n"
			"mov $157, %%rax\n"
			"syscall\n" :: "g"(option), "g"(arg2), "g"(arg3), "g"(arg4), "g"(arg5));
	asm("mov %%rax, %0" : "=r"(ret));
	return (int)ret;
}

int _read(long fd, char *buf, unsigned long len)
{
	 long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov %2, %%rdx\n"
                        "mov $0, %%rax\n"
                        "syscall" : : "g"(fd), "g"(buf), "g"(len));
        asm("mov %%rax, %0" : "=r"(ret));
        return (int)ret;
}

long _write(long fd, char *buf, unsigned long len)
{
	long ret;
	__asm__ volatile(
			"mov %0, %%rdi\n"
			"mov %1, %%rsi\n"
			"mov %2, %%rdx\n"
			"mov $1, %%rax\n"
			"syscall" : : "g"(fd), "g"(buf), "g"(len));
	asm("mov %%rax, %0" : "=r"(ret));
	return ret;
}

int _fstat(long fd, void *buf)
{
	long ret;
	__asm__ volatile(
			"mov %0, %%rdi\n"
			"mov %1, %%rsi\n"
			"mov $5, %%rax\n"
			"syscall" : : "g"(fd), "g"(buf));
	asm("mov %%rax, %0" : "=r"(ret));
	return (int)ret;
}

long _kill(unsigned int pid, unsigned int sig)
{
	long ret;
	__asm__ volatile(
			"mov %0, %%rdi\n"
			"mov %1, %%rsi\n"
			"mov $62, %%rax\n"
			"syscall" : : "g"(pid), "g"(sig));
	asm ("mov %%rax, %0" : "=r"(ret));
}

long _open(const char *path, unsigned long flags)
{
	long ret;
	__asm__ volatile(
			"mov %0, %%rdi\n"
			"mov %1, %%rsi\n"
			"mov $2, %%rax\n"
			"syscall" : : "g"(path), "g"(flags));
	asm ("mov %%rax, %0" : "=r"(ret));		
	
	return ret;
}

int _close(unsigned int fd)
{
	long ret;
	__asm__ volatile(
			"mov %0, %%rdi\n"
			"mov $3, %%rax\n"
			"syscall" : : "g"(fd));
	return (int)ret;
}

long _ptrace(long request, long pid, void *addr, void *data)
{
	long ret;

	__asm__ volatile(
			"mov %0, %%rdi\n"
			"mov %1, %%rsi\n"
			"mov %2, %%rdx\n"
			"mov %3, %%r10\n"
			"mov $101, %%rax\n"
			"syscall" : : "g"(request), "g"(pid), "g"(addr), "g"(data));
	asm("mov %%rax, %0" : "=r"(ret));
	
	return ret;
}

int _mprotect(void * addr, unsigned long len, int prot)
{
	unsigned long ret;
	__asm__ volatile(
			"mov %0, %%rdi\n"
			"mov %1, %%rsi\n"
			"mov %2, %%rdx\n"
			"mov $10, %%rax\n"
			"syscall" : : "g"(addr), "g"(len), "g"(prot));
	asm("mov %%rax, %0" : "=r"(ret));
	
	return (int)ret;
}

void *_mmap(void *addr, unsigned long len, unsigned long prot, unsigned long flags, long fd, unsigned long off)
{
	long mmap_fd = fd;
	unsigned long mmap_off = off;
	unsigned long mmap_flags = flags;
	unsigned long ret;

	__asm__ volatile(
			 "mov %0, %%rdi\n"
			 "mov %1, %%rsi\n"
			 "mov %2, %%rdx\n"
			 "mov %3, %%r10\n"
			 "mov %4, %%r8\n"
			 "mov %5, %%r9\n"
			 "mov $9, %%rax\n"
			 "syscall\n" : : "g"(addr), "g"(len), "g"(prot), "g"(flags), "g"(mmap_fd), "g"(mmap_off));
	asm ("mov %%rax, %0" : "=r"(ret));		
	return (void *)ret;
}

int _munmap(void *addr, size_t len)
{
	long ret;
	__asm__ volatile(
			"mov %0, %%rdi\n"
			"mov %1, %%rsi\n"
			"mov $11, %%rax\n"
			"syscall" :: "g"(addr), "g"(len));
	asm ("mov %%rax, %0" : "=r"(ret));
        return (int)ret;
}

int _getdents64(unsigned int fd, struct linux_dirent64 *dirp,
                    unsigned int count)
{
	long ret;
	__asm__ volatile(
			"mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov %2, %%rdx\n"
 			"mov $217, %%rax\n"
			"syscall" :: "g"(fd), "g"(dirp), "g"(count));
	asm ("mov %%rax, %0" : "=r"(ret));
        return (int)ret;
}


int _nanosleep(struct timespec *req, struct timespec *rem)
{
	unsigned long ret;
	__asm__ volatile(
		"mov %0, %%rdi\n"
		"mov %1, %%rsi\n"
		"mov $35, %%rax\n"
		"syscall" :: "g"(req), "g"(rem));
	 asm ("mov %%rax, %0" : "=r"(ret));
	return (int)ret;
}



int _getuid(void)
{
	unsigned long ret;
	__asm__ volatile("mov $102, %rax\n"
			 "syscall");
  	 asm ("mov %%rax, %0" : "=r"(ret));
        return (int)ret;
}

int _geteuid(void)
{
        unsigned long ret;
        __asm__ volatile("mov $107, %rax\n"
                         "syscall");
         asm ("mov %%rax, %0" : "=r"(ret));
        return (int)ret;
}


void Exit(long status)
{
        __asm__ volatile("mov %0, %%rdi\n"
                         "mov $60, %%rax\n"
                         "syscall" : : "r"(status));
}

