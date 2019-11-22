#include <linux/mm.h>
#include <asm/unistd.h>
#include <asm/domain.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/bug.h>
#include <asm/tlbflush.h>


#define arch_max_udom() 16

extern int udom_total; /* total udoms as per device tree */
extern u32 initial_allocation_mask; /*  bits set for the initially allocated keys */
extern u32 reserved_allocation_mask; /* bits set for reserved keys */


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


	mm_set_udom_allocated(mm, ret);


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


// this should check if a task has the right capabilty to get udom info
// it shouldn\t get info to all tasks, so basically should check the task caps
static inline
int udom_get(int udom)
{	
		unsigned long dacr = 0;						
	unsigned int domain = get_domain();	
		domain &= domain_mask(udom);
	

	__asm__ __volatile__(
            "mrc p15, 0, %[result], c3, c0, 0\n"
            : [result] "=r" (dacr) : );


	int ret= (domain >> (2 * (udom)));	

	return  ret;	

}

static inline
int udom_set(int udom, unsigned val)
{
	unsigned int domain = get_domain();		
	domain &= ~domain_mask(udom);			
	domain = domain | domain_val(udom, val);	
	set_domain(domain);				

	return 0;
	
}



/*
 * Try to dedicate one of the protection keys to be used as an
 * execute-only protection key.
 */
extern int __execute_only_udom(struct mm_struct *mm);
static inline int execute_only_udom(struct mm_struct *mm)
{

	return __execute_only_udom(mm);
}