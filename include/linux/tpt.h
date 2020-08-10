#ifndef _LINUX_TPT_H
#define _LINUX_TPT_H


#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/tpt_mm.h>

//#define TPT_LOGGING
#ifdef TPT_LOGGING
#define slog(level, fmt, args...) printk(level fmt, ## args...)
#else
#define slog(level, fmt, args...) do{ }while(0)
#endif

/// Ribbons struct metadata ///
struct smv_struct {
    int smv_id;
    atomic_t ntask;       // number of tasks running in this smv
    DECLARE_BITMAP(memdom_bitmapJoin, TPT_ARRAY_SIZE); // Bitmap of memdoms.  set to 1 if this smv is in memdom[i], 0 otherwise.
    struct mutex smv_mutex;  // lock smv struct to prevent race condition   
};


// internal memory managment functions

struct mmu_gather;
#define allocate_smv()         (kmem_cache_alloc(smv_cachep, GFP_KERNEL)) // SLAB cache for smv_struct structure 
#define free_smv(smv)       (kmem_cache_free(smv_cachep, smv))
extern void smv_init(void);      // Called by init/main.c 
pgd_t *smv_alloc_pgd(struct mm_struct *mm, int smv_id);
void smv_free_pgd(struct mm_struct *mm, int smv_id);
void smv_free_pgtables(struct mmu_gather *tlb, struct vm_area_struct *vma,
                    		unsigned long floor, unsigned long ceiling);
void switch_smv(struct task_struct *prev_tsk, struct task_struct *next_tsk, struct mm_struct *prev_mm, struct mm_struct *next_mm);
void smv_free_mmap(struct mm_struct *mm, int smv_id);



//exported functions to user space 

int smv_create(void);
int smv_kill(int smv_id, struct mm_struct *mm);
void free_all_smvs(struct mm_struct *mm);
int get_curr_smv_id(void);
int smv_exists(int smv_id);
int is_smv_joined_mdom(int memdom_id, int smv_id);
int smv_leave_mdom(int memdom_id, int smv_id, struct mm_struct *mm);
int smv_attach_mdom(int memdom_id, int smv_id);
int register_smv_thread(int smv_id);
//int smv_main_init(void);



#endif //_LINUX_TPT_H//
