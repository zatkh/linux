#include <linux/tpt.h>
#include <linux/mdom.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/mm_types.h>
#include <linux/sched.h>
#include <linux/gfp.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <linux/smp.h>
#include <linux/mm.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>

#define PGALLOC_GFP GFP_KERNEL | __GFP_NOTRACK | __GFP_REPEAT | __GFP_ZERO

/* SLAB cache for smv_struct structure  */
static struct kmem_cache *smv_cachep;


void smv_init(void){
    smv_cachep = kmem_cache_create("smv_struct",
                                      sizeof(struct smv_struct), 0,
                                      SLAB_HWCACHE_ALIGN, NULL);
    if( !smv_cachep ) {
        printk(KERN_ERR "[%s] smv slab initialization failed...\n", __func__);
    } else{
        printk(KERN_INFO "[%s] smv slab initialized\n", __func__);
    }
}


/* Allocate a pgd for the new smv */
pgd_t *smv_alloc_pgd(struct mm_struct *mm, int smv_id){
    pgd_t *pgd = NULL;

    if( !mm->using_smv ) {
        printk(KERN_ERR "[%s] Error: current mm is not using smv model.\n", __func__);
        return NULL;
    }

    /* Allcoate pgd. MAIN_THREAD with smv id 0 already has pgd, just record it */
    if( smv_id == 0 ) {    
        pgd = mm->pgd;
        mm->page_table_lock_smv[smv_id] = mm->page_table_lock;
    } else {
        pgd = pgd_alloc(mm); // see implementation in pgtable.c
        if( unlikely(!pgd) ) { 
            printk(KERN_ERR "[%s] failed to allocate new pgd.\n", __func__);
            return NULL;
        }
        /* Init page table lock */
        spin_lock_init(&mm->page_table_lock_smv[smv_id]);
    }

    /* Assign page table directory to mm_struct for smv_id */
    mm->pgd_smv[smv_id] = pgd;

    slog(KERN_INFO "[%s] smv %d pgd %p\n", __func__, smv_id, mm->pgd_smv[smv_id]);
    return pgd;
}

/* Free a pgd for smv */
void smv_free_pgd(struct mm_struct *mm, int smv_id){
    free_page((unsigned long)mm->pgd_smv[smv_id]);
}

/* Hook for security context switch from one smv to another (change secure memory view) 
 */
void switch_smv(struct task_struct *prev_tsk, struct task_struct *next_tsk, 
                   struct mm_struct *prev_mm, struct mm_struct *next_mm){

    /* Skip smv context switch if the next tasks is not in any smvs, or if next_mm is NULL */
    if( (next_tsk && next_tsk->smv_id == -1) || 
         next_mm == NULL) {
        return;
    }
}

// implemented in memory.c 
void smv_free_pgtables(struct mmu_gather *tlb, struct vm_area_struct *vma,
                    		unsigned long floor, unsigned long ceiling){
    while (vma) {
		struct vm_area_struct *next = vma->vm_next;
		unsigned long addr = vma->vm_start;
		free_pgd_range(tlb, addr, vma->vm_end, floor, next? next->vm_start: ceiling);
		vma = next;
    }
}

// Free page tables for a smv and caller must hold the mm semaphore 
void smv_free_mmap(struct mm_struct *mm, int smv_id){
    struct vm_area_struct *vma = mm->mmap;
	struct mmu_gather tlb;

    /* Can happen if dup_mmap() received an OOM */
	if (!vma) {
		return;
    }

    /* Leave the chores of cleaning page tables to the main thread when the process exits the system by do_exit() */
    if( smv_id == MAIN_THREAD ) {
        return;
    }

   
     // should we shootdown TLB when each threads cleaning its own pagetables metadata

    else {
        slog(KERN_INFO "[%s] Free pgtables for smv %d\n", __func__, smv_id);
        slog(KERN_INFO "[%s] Before smv_free_mmap mm: %p, nr_pmds: %ld, nr_ptes: %ld\n", 
                __func__, mm, atomic_long_read(&mm->nr_pmds), atomic_long_read(&mm->nr_ptes));
        tlb_gather_mmu(&tlb, mm, 0, -1);
        update_hiwater_rss(mm);

        /* Overwrite the smv_id to be freed. tlb_gather_mmu set tlb.smv_id to be current->smv_id.
         * However, this function could be called by the main thread (smv_id = 0) when the process 
         * exiting the system to free the page tables for other smvs (smv_id !=0). 
         * So here we need to set the correct smv_id for unmap_vmas and smv_free_pgtables. */
        tlb.smv_id = smv_id; 

        /* Do the actual job of freeing page tables */
        unmap_vmas(&tlb, vma, 0, -1);
        smv_free_pgtables(&tlb, vma, FIRST_USER_ADDRESS, USER_PGTABLES_CEILING);       

       	tlb_finish_mmu(&tlb, 0, -1);
        slog(KERN_INFO "[%s] After smv_free_mmap mm: %p, nr_pmds: %ld, nr_ptes: %ld\n", 
                __func__, mm, atomic_long_read(&mm->nr_pmds), atomic_long_read(&mm->nr_ptes));
    }
}
