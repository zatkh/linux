

#include <asm/udom.h>

#include "lsm.h"



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

asmlinkage int sys_udom_free(unsigned long udom)
{

	int ret;
	unsigned long dacr = 0;

	down_write(&current->mm->mmap_sem);


	modify_domain(udom,DOMAIN_CLIENT);

	mm_udom_free(current->mm, udom);

	__asm__ __volatile__(
            "mrc p15, 0, %[result], c3, c0, 0\n"
            : [result] "=r" (dacr) : );
    printk("allocated udom:%d, dacr=0x%lx\n",udom, dacr);

out:
	up_write(&current->mm->mmap_sem);
	return ret;


}
