#include <linux/device.h>
#include <linux/lsm_hooks.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/kernel.h>
#include <linux/binfmts.h>
#include <linux/types.h>
#include <linux/security.h>
#include <linux/file.h>
#include <linux/dcache.h>
#include <linux/cred.h>
#include <linux/uaccess.h>
#include <linux/mman.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>

#include <azure-sphere/security.h>

#include <asm/syscall.h>
#include <linux/compat.h>
#include <linux/slab.h>
#include <linux/syscalls.h>	
#include <linux/mm.h>

#include <asm/elf.h>
#include <asm/unistd.h>
#include <asm/domain.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/bug.h>
#include <asm/tlbflush.h>


#include "lsm.h"

#define arch_max_udom() 16

int udom_total; /* total udoms as per device tree */
u32 initial_allocation_mask; /*  bits set for the initially allocated keys */
u32 reserved_allocation_mask; /* bits set for reserved keys */


static inline bool mm_udom_is_allocated(struct mm_struct *mm, int udom)
{
	if (udom < 3 || udom >= arch_max_udom())
		return false;

	/* Reserved keys are never allocated. */
	if (__mm_udom_is_reserved(udom))
		return false;

	return __mm_udom_is_allocated(mm, udom);
}


/*
 * Returns a positive, 4-bit key on success, or -1 on failure.
 */
static inline
int mm_udom_alloc(struct mm_struct *mm)
{
	/*
	 * Note: this is the one and only place we make sure
	 * that the udom is valid as far as the hardware is
	 * concerned.  The rest of the kernel trusts that
	 * only good, valid udoms come out of here.
	 */
	u16 all_udoms_mask = ((1U << arch_max_udom()) - 1);
	int ret;

	/*
	 * Are we out of udoms?  We must handle this specially
	 * because ffz() behavior is undefined if there are no
	 * zeros.
	 */
	if (mm_udom_allocation_map(mm) == all_udoms_mask)
		return -1;

	ret = ffz(mm_udom_allocation_map(mm));//skip the first three domains

    printk("ret:%d \n",ret);

	mm_set_udom_allocated(mm, ret);
	    printk("ret:%d \n",ret);


	return ret;
}


static inline
int mm_udom_free(struct mm_struct *mm, int udom)
{
	if (!mm_udom_is_allocated(mm, udom))
		return -EINVAL;

	mm_set_udom_free(mm, udom);

	return 0;
}


//set current task labels
asmlinkage long sys_udom_alloc(unsigned long flags, unsigned long init_val)
{

	int udom;
	int ret;
	unsigned long dacr = 0;

	/* No flags supported yet. */
	if (flags)
		return -EINVAL;
	/* check for unsupported init values */
	//if (init_val & ~UDOM_ACCESS_MASK)
		//return -EINVAL;

	down_write(&current->mm->mmap_sem);
	udom = mm_udom_alloc(current->mm);

	ret = -ENOSPC;
	if (udom == -1)
		goto out;

	modify_domain(udom,init_val);

	ret = udom;

	__asm__ __volatile__(
            "mrc p15, 0, %[result], c3, c0, 0\n"
            : [result] "=r" (dacr) : );
    printk("allocated udom:%d, dacr=0x%lx\n",udom, dacr);

out:
	up_write(&current->mm->mmap_sem);
	return ret;
}