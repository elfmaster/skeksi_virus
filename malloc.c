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

/*
 * This heap implementation was originally written for Maya's Veil
 * and is being re-used as the generic heap that should be used for
 * any dynamic memory allocation done by any code in the runtime_engine
 * area.
 *
 */


#include "private.h"
#include "heap.h"


#define INIT_MALLOC_SIZE 4096 << 10
#define MAX_HEAP_BINS 32
#define HEAP_BLOCK_SIZE 16 // XXX NOTE: Changed from 512 to 16 (Much more space efficient for hash map)
#define CHUNK_ROUNDUP(x)(x + HEAP_BLOCK_SIZE & ~(HEAP_BLOCK_SIZE - 1))
#define CHUNK_UNUSED_INITIALIZER 0xFFFFFFFF
#define MALLOC_KEY_LEN 0x8 /* Used for encrypted chunks */

#define MALLOC(len) heap_alloc(len)
#define FREE(ptr) heap_free(ptr)

struct chunkData {
        unsigned long chunkVaddr;
        unsigned int chunkSize;
        unsigned int chunkOffset; 
};

struct mHandle {
        unsigned char *bin;
        unsigned int memOff;
        unsigned int binSize;
        unsigned long baseVaddr;
        void *indexTable;
        struct chunkData *chunkData; // we store these in indexTable mapping
        int chunkCount;
        int initialized;
}; 

struct mHandle mHandle[MAX_HEAP_BINS] __attribute__((section(".data"))) = { [0 ... MAX_HEAP_BINS - 1] = 0};
unsigned int ActiveBin __attribute__((section(".data"))) = 0;

void heap_free(void *);
void * heap_alloc(unsigned int);
void * malloc_crypto_store(unsigned char *, const void *, unsigned int);
int malloc_crypto_load(unsigned char *, const void *, unsigned int, void *);

/*
 * Simple implementation of malloc
 **/

/*  
 *  Each bin has a chunk index 'void *indexTable'
 *  which contains an array of 'struct chunkData'.
 *  Chunks are 16 bytes, and no memory request 
 *  ever returns less than a chunk size. This 
 *  works for our purposes, but could obviously
 *  be refined.
 *  
 *  [INDEX 0]___________________________________
           \       \      \              \
 *  [BIN 0][CHUNK][CHUNK][CHUNK][EMPTY][CHUNK]
 *   
 *  [INDEX 1]___________________________________  
 *          \                    \
 *  [BIN 1][CHUNK][EMPTY][EMPTY][CHUNK][EMPTY]
 *
 *  HEAP CHUNK(BLOCK) SIZE: 16B
 *  MAXIMUM ALLOCATION SIZE PER ALLOCATION: 4MB or (4194304 Bytes) (adjust through INIT_MALLOC_SIZE)
 *  MAXIMUM HEAP CAPCITY: 134MB or (134217696 bytes) (adjust through MAX_HEAP_BINS)
 *  
 */

void * heap_alloc(unsigned int len)
{
	int i;

	/*
	 * The first call to malloc() will create the first heap bin
	 * with mmap(), and initialize base values.
	 */
	if (mHandle[ActiveBin].initialized == 0) {
		DEBUG_PRINT("initializing bin\n");
		mHandle[ActiveBin].initialized = 1;
		mHandle[ActiveBin].bin = _mmap((void *)0, INIT_MALLOC_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);		
		if (mHandle[ActiveBin].bin == MAP_FAILED) {
			_printf("[!] libdarkley: Unable to initialize malloc()\n");
			Exit(-1);
		}
#if DEBUG
		_printf("[+] libdarkley: internal heap allocation base: 0x%x\n", mHandle[ActiveBin].bin);
#endif
		mHandle[ActiveBin].binSize = INIT_MALLOC_SIZE;
		mHandle[ActiveBin].memOff = 0;
		mHandle[ActiveBin].baseVaddr = (unsigned long)mHandle[ActiveBin].bin;
		mHandle[ActiveBin].indexTable = _mmap((void *)0, INIT_MALLOC_SIZE / (sizeof(long) * 4), PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
		if (mHandle[ActiveBin].indexTable == MAP_FAILED) {
			_printf("[!] libdarkley: Unable to initialize malloc index table\n");
			Exit(-1);
		}
		mHandle[ActiveBin].chunkData = (struct chunkData *)mHandle[ActiveBin].indexTable;
		DEBUG_PRINT("indexTable: %x\n", mHandle[ActiveBin].indexTable);
	}
	
	/*
	 * If we go into this condition it means we have exceeded the current
	 * bin size, and must allocate a new heap bin.
	 */
	if ((mHandle[ActiveBin].memOff + CHUNK_ROUNDUP(len)) >= INIT_MALLOC_SIZE) {
#if DEBUG
		_printf("[DEBUG] incrementing ActiveBin to %d\n", ActiveBin + 1);
#endif
		ActiveBin++;
		if (ActiveBin > MAX_HEAP_BINS - 1) {
			_printf("[!] libdarkley: Exhausted heap resources\n");
			Exit(-1);
		}
		
		mHandle[ActiveBin].bin = _mmap((void *)0, INIT_MALLOC_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
		if (mHandle[ActiveBin].bin == MAP_FAILED) {
			_printf("[!] libdarkley: Unable to map new heap bin\n");
			Exit(-1);
		} 
		mHandle[ActiveBin].binSize = INIT_MALLOC_SIZE;
		mHandle[ActiveBin].initialized = 1;
		mHandle[ActiveBin].memOff = 0; 
		mHandle[ActiveBin].baseVaddr = (unsigned long)mHandle[ActiveBin].bin;
		mHandle[ActiveBin].indexTable = _mmap((void *)0, INIT_MALLOC_SIZE / (sizeof(long) * 4), PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
		if (mHandle[ActiveBin].indexTable == MAP_FAILED) {
			_printf("[!] libdarkley: Unable to initialize malloc index table for bin(%d)\n", ActiveBin);
			Exit(-1);
		}
		mHandle[ActiveBin].chunkData = (struct chunkData *)mHandle[ActiveBin].indexTable;
	} 	
	/*
	 * First look for a free'd chunk that could be re-used.
	 */
	for (i = 0; i < mHandle[ActiveBin].chunkCount; i++) {
		if (mHandle[ActiveBin].chunkData[i].chunkVaddr == CHUNK_UNUSED_INITIALIZER) {
#if DEBUG
			_printf("[DEBUG MALLOC] Found a freed chunk-> bin(%d) Vaddr: %x chunk %d\n", ActiveBin, mHandle[ActiveBin].chunkData[i].chunkVaddr, i);
#endif
			if (CHUNK_ROUNDUP(len) <= mHandle[ActiveBin].chunkData[i].chunkSize) {
#if DEBUG
			_printf("[DEBUG MALLOC] Using the free chunk(%d) at Vaddr: %x bin(%d)\n", i, mHandle[ActiveBin].chunkData[i].chunkVaddr, ActiveBin);
#endif
				
				mHandle[ActiveBin].chunkData[i].chunkVaddr = (unsigned long)&(mHandle[ActiveBin].bin[mHandle[ActiveBin].chunkData[i].chunkOffset]);
				return &(mHandle[ActiveBin].bin[mHandle[ActiveBin].chunkData[i].chunkOffset]);	
			}
		}
	}

	/*
	 * Do index table entry for malloc request. This helps keep track
	 * of chunks. 
	 */
#if DEBUG
	_printf("[DEBUG MALLOC] Using chunk(%d) bin(%d)\n", mHandle[ActiveBin].chunkCount, ActiveBin); // mHandle[ActiveBin].chunkData[mHandle[ActiveBin].chunkCount].chunkVaddr);
#endif
	mHandle[ActiveBin].chunkData[mHandle[ActiveBin].chunkCount].chunkVaddr = (unsigned long) &(mHandle[ActiveBin].bin[mHandle[ActiveBin].memOff]); 
	mHandle[ActiveBin].chunkData[mHandle[ActiveBin].chunkCount].chunkSize =  CHUNK_ROUNDUP(len);
	mHandle[ActiveBin].chunkData[mHandle[ActiveBin].chunkCount].chunkOffset = mHandle[ActiveBin].memOff + CHUNK_ROUNDUP(len);
	mHandle[ActiveBin].chunkCount++;

	/* Increase offset into heap bin */
	mHandle[ActiveBin].memOff += CHUNK_ROUNDUP(len);

	/* Return pointer to chunk */
	return &(mHandle[ActiveBin].bin[mHandle[ActiveBin].memOff - CHUNK_ROUNDUP(len)]); 		
} 

void heap_free(void *mem)
{
	int i, j;
	unsigned long current = (unsigned long)(void *)mem;
	unsigned long vaddr;  
	unsigned int size; 
	unsigned int off; 
		
	for (j = 0; j <= ActiveBin; j++) {
		for (i = 0; i <= mHandle[j].chunkCount; i++) {

			vaddr = mHandle[j].chunkData[i].chunkVaddr;
			size = mHandle[j].chunkData[i].chunkSize;
	
			if (current >= vaddr && current < vaddr + size) {
#ifdef DEBUG	
				_printf("free() found chunk, now freeing pointer.\n");
#endif
				/* 
				 * We mark chunkVaddr as CHUNK_UNUSED so that we can use this
				 * chunk again by another allocation request.
				 *
				 */
				mHandle[j].chunkData[i].chunkVaddr = CHUNK_UNUSED_INITIALIZER; 
				
				/* Point it back to the beggining of chunk */
				mem = (void *)vaddr;
				
				/* initialize chunk with 0's as its empty */
				Memset(mem, 0, mHandle[j].chunkData[i].chunkSize);
				
				/* Initialize ptr back to NULL */
				mem = NULL; // initialize pointer to NULL
				goto done;
			}
		}
	}
done:
	return;
			
}

void * darkley_heap_store(unsigned char *key, const void *data, unsigned int len)
{	
	unsigned int i, k;
	unsigned char *ptr;

	ptr = heap_alloc(len);
	_memcpy((unsigned char *)ptr, (unsigned char *)data, len);
	/*
	 * In some instances we don't want a key. For instance when
	 * storing the keys that decrypt the keys. Those top level
	 * keys shouldn't be encrypted by yet another set of keys,
	 * as the list would go on of keys to keys.
	 */
	if (key == NULL) {
#ifdef DEBUG
		_printf("[!] libdarkley: malloc_crypto_store. (mode: no key)\n");
#endif
		for (i = 0; i < len; i++) 
			ptr[i] ^= ((0xE * i) & 0xff); 
		return (void *)ptr;
	}
	
#ifdef DEBUG
	_printf("[!] libdarkley: malloc_crypto_store. (mode: 64bit key)\n");
#endif
	for (i = 0, k = 0; i < len; i++) {
		ptr[i] ^= key[k++];
		if (k > MALLOC_KEY_LEN)
			k = 0;
	}
	return (void *)ptr;
	
} 

int darkley_heap_load(unsigned char *key, const void *mem, unsigned int len, void *dst)
{
 	int i, j, k, l, found = 0;
        unsigned long current = (unsigned long)(void *)mem;
        unsigned long vaddr;
        unsigned int size;
	unsigned char *d = (unsigned char *)dst;
	unsigned char *m = (unsigned char *)mem;

        for (j = 0; j <= ActiveBin; j++) {
                for (i = 0; i <= mHandle[j].chunkCount; i++) {

                        vaddr = mHandle[j].chunkData[i].chunkVaddr;
                        size = mHandle[j].chunkData[i].chunkSize;

                        if (current >= vaddr && current < vaddr + size) {
				if (current > vaddr)
					m = (unsigned char *)mem - (current - vaddr);
				if (key == NULL) {
					for (l = 0; l < len; l++)
						d[l] = m[l] ^ ((0xE * l) & 0xff);
					found++;
					break;
				} else {
					for (l = 0, k = 0; l < len; l++) {
						d[l] = m[l] ^ key[k++];
						if (k > MALLOC_KEY_LEN)
							k = 0;
					}
					found++;	
					break;
				}
											
	
			}
		}
	}
#if DEBUG
	if (found)
		_printf("malloc_crypto_load() succeeded\n");
#endif
	return 0;

}	
