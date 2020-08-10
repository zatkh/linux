#include <linux/tpt.h>
#include <linux/mdom.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mm.h>

/* SLAB cache for smv_struct structure  */
static struct kmem_cache *memdom_cachep;

/** void memdom_init(void)
 *  Create slab cache for future memdom_struct allocation This
 *  is called by start_kernel in main.c 
 */
void memdom_init(void){
    memdom_cachep = kmem_cache_create("memdom_struct",
                                      sizeof(struct memdom_struct), 0,
                                      SLAB_HWCACHE_ALIGN , NULL);
    if( !memdom_cachep ) {
        printk(KERN_INFO "[%s] memdom slabs initialization failed...\n", __func__);
    } else{
        printk(KERN_INFO "[%s] memdom slabs initialized\n", __func__);
    }
}

// Initialize vma's owner to the main thread, only called by the main thread 
int memdom_claim_all_vmas(int memdom_id){
    struct vm_area_struct *vma;
    struct mm_struct *mm = current->mm;
    int vma_count = 0;

    if( memdom_id > LAST_MEMDOM_INDEX ) {
        printk(KERN_ERR "[%s] Error, out of bound: memdom %d\n", __func__, memdom_id);
        return -1;
    }
    
   	down_write(&mm->mmap_sem);
  	for (vma = mm->mmap; vma; vma = vma->vm_next) {
        vma->memdom_id = MAIN_THREAD;
        vma_count++;
    }
   	up_write(&mm->mmap_sem);

    slog(KERN_INFO "[%s] Initialized %d vmas to be in memdom %d\n", __func__, vma_count, memdom_id);
    return 0;
}
