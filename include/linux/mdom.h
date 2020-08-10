#ifndef _LINUX_MEMDOM_H
#define _LINUX_MEMDOM_H

#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/tpt_mm.h>

/* Permission */
#define MEMDOM_READ             0x00000001
#define MEMDOM_WRITE            0x00000002
#define MEMDOM_EXECUTE          0x00000004
#define MEMDOM_ALLOCATE         0x00000008

struct memdom_struct {
    int memdom_id;    
    struct mutex memdom_mutex;
    DECLARE_BITMAP(smv_bitmapRead, TPT_ARRAY_SIZE); // Bitmap of smv.  Set to 1 if smv[i] can read this memdom, 0 otherwise.
    DECLARE_BITMAP(smv_bitmapWrite, TPT_ARRAY_SIZE); // Bitmap of smv.  Set to 1 if smv[i] can write this memdom, 0 otherwise.
    DECLARE_BITMAP(smv_bitmapExecute, TPT_ARRAY_SIZE); // Bitmap of smv.  Set to 1 if smv[i] can execute data in this memdom, 0 otherwise.
    DECLARE_BITMAP(smv_bitmapAllocate, TPT_ARRAY_SIZE); // Bitmap of smv.  Set to 1 if smv[i] can allocate data in this memdom, 0 otherwise.
};

// internal memory managment functions

#define allocate_memdom()   (kmem_cache_alloc(memdom_cachep, GFP_KERNEL))
#define free_memdom(memdom) (kmem_cache_free(memdom_cachep, memdom))
extern void memdom_init(void);
int memdom_claim_all_vmas(int memdom_id);


//exported functions to user space 

int memdom_main_id(void);
int memdom_private_id(void);
int memdom_query_id(unsigned long addr);
int memdom_create(void);
int memdom_kill(int memdom_id, struct mm_struct *mm);
void free_all_memdoms(struct mm_struct *mm);
int memdom_priv_add(int memdom_id, int smv_id, int privs);
int memdom_priv_del(int memdom_id, int smv_id, int privs);
int memdom_priv_get(int memdom_id, int smv_id);
int memdom_mmap_register(int memdom_id);
unsigned long memdom_munmap(unsigned long addr);


#endif

