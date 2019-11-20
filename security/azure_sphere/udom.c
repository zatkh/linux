
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

#include <asm/elf.h>
#include <asm/udom.h>

#include "lsm.h"

int udom_total; /* total udoms as per device tree */
u32 initial_allocation_mask; /*  bits set for the initially allocated keys */
u32 reserved_allocation_mask; /* bits set for reserved keys */



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

	int udom_client_acc= udom_get(DOMAIN_KERNEL);
	if(udom_client_acc==DOMAIN_CLIENT)
	    printk("client udom acc:%d\n",udom_client_acc);


	__asm__ __volatile__(
            "mrc p15, 0, %[result], c3, c0, 0\n"
            : [result] "=r" (dacr) : );
    printk("allocated udom:%d, dacr=0x%lx\n",udom, dacr);

out:
	up_write(&current->mm->mmap_sem);
	return ret;


}

int __execute_only_udom(struct mm_struct *mm)
{
	bool need_to_set_mm_udom = false;
	int execute_only_udom = mm->context.execute_only_udom;
	int ret;

	/* Do we need to assign a udom for mm's execute-only maps? */
	if (execute_only_udom == -1) {
		/* Go allocate one to use, which might fail */
		execute_only_udom = mm_udom_alloc(mm);
		if (execute_only_udom < 0)
			return -1;
		need_to_set_mm_udom = true;
	}

	/*
	 * We do not want to go through the relatively costly
	 * dance to set DACR if we do not need to.  Check it
	 * first and assume that if the execute-only udom is
	 * write-disabled that we do not have to set it
	 * ourselves.  We need preempt off so that nobody
	 * can make fpregs inactive.
	 */
	/*preempt_disable();
	if (!need_to_set_mm_udom &&
	    current->thread.fpu.initialized &&
	    !__pkru_allows_read(read_pkru(), execute_only_udom)) {
		preempt_enable();
		return execute_only_udom;
	}
	preempt_enable();
*/
	/*
	 * Set up PKRU so that it denies access for everything
	 * other than execution.
	 */
	//ret = arch_set_user_udom_access(current, execute_only_udom,
	//		PKEY_DISABLE_ACCESS);
	/*
	 * If the PKRU-set operation failed somehow, just return
	 * 0 and effectively disable execute-only support.
	 */
	if (ret) {
		mm_set_udom_free(mm, execute_only_udom);
		return -1;
	}

	/* We got one, store it and use it from here on out */
	if (need_to_set_mm_udom)
		mm->context.execute_only_udom = execute_only_udom;
	return execute_only_udom;
}

