/*
* DIFC Linux Security Module
* Author: Yuqiong Sun <yus138@cse.psu.edu>
*/

#include <linux/xattr.h>
#include <linux/pagemap.h>
#include <linux/mount.h>
#include <linux/stat.h>
#include <linux/kd.h>
#include <asm/ioctls.h>
#include <linux/dccp.h>
#include <linux/mutex.h>
#include <linux/pipe_fs_i.h>
#include <linux/audit.h>
#include <linux/magic.h>
#include <linux/dcache.h>
#include <linux/personality.h>
#include <linux/msg.h>
#include <linux/shm.h>
#include "difc.h"


#ifdef CONFIG_EXTENDED_LSM_DIFC
struct kmem_cache *tag_struct;
static struct kmem_cache *difc_obj_kcache;
static struct kmem_cache *difc_caps_kcache;

atomic_t max_caps_num;
typedef label_t* labelList_t;
static int debug = 1;

#define alloc_cap_segment() kmem_cache_zalloc(difc_caps_kcache, GFP_KERNEL)
#define free_cap_segment(s) kmem_cache_free(difc_caps_kcache, s)

#define SECRECY_LABEL  0
#define INTEGRITY_LABEL  1

#define ADD_LABEL     0
#define REMOVE_LABEL  1
#define REPLACE_LABEL 2

#define CAPS_INIT 1

#define difc_lsm_debug(fmt, arg...)					\
	do {							\
		if (debug)					\
			printk(KERN_ERR "(pid %d) %s: [%s]: " fmt ,	\
			       current->pid, "[difc_lsm]" , __FUNCTION__ , 	\
				## arg);			\
	} while (0)

/* labellist iterator */
#define list_for_each_label(index, l, head)	\
	for(index = 1; index <= *(head) && ({l = head[index]; 1; }); index++)

/* caplist iterator */
#define list_for_each_cap(index, l, n, head)				\
	list_for_each_entry(n, &(head), list)				\
	for(index = 1; index <= (n)->caps[0] && ({l = (n)->caps[index]; 1; }); index++)


#endif /*CONFIG_EXTENDED_LSM_DIFC */


static struct task_difc *new_task_difc(gfp_t gfp) {
	struct task_difc *tsp;
	tsp = kzalloc(sizeof(struct task_difc), gfp);
	
	if (!tsp)
		return NULL;
	tsp->confined = false;
	INIT_LIST_HEAD(&tsp->slabel);
	INIT_LIST_HEAD(&tsp->ilabel);
	INIT_LIST_HEAD(&tsp->olabel);
	
	return tsp;
} 

static void difc_free_label(struct list_head *label) {
	struct tag *t, *t_next;
	list_for_each_entry_safe(t, t_next, label, next) {
		list_del_rcu(&t->next);
		kmem_cache_free(tag_struct, t);
	}
}

static int difc_copy_label(struct list_head *old, struct list_head *new) {
	struct tag *t;
	
	list_for_each_entry(t, old, next) {
		struct tag *new_tag;
		new_tag = kmem_cache_alloc(tag_struct, GFP_NOFS);
		if (new_tag == NULL)
			goto out;
		new_tag->content = t->content;
		list_add_tail(&new_tag->next, new);
	}
	return 0;

out:
	return -ENOMEM;
}

static struct inode_difc *inode_security_novalidate(struct inode *inode) {
	return inode->i_security;
}

static struct inode_difc *new_inode_difc(void) {
	struct inode_difc *isp;
	struct task_difc *tsp;
	int rc = -ENOMEM;
	
	isp = kzalloc(sizeof(struct inode_difc), GFP_NOFS);
	
	if(!isp)
		return NULL;

	INIT_LIST_HEAD(&isp->slabel);
	INIT_LIST_HEAD(&isp->ilabel);

	tsp = current_security();

	/*
	* Label of inode is the label of the task creating the inode
	*/

	rc = difc_copy_label(&tsp->slabel, &isp->slabel);
	if (rc < 0)
		goto out;

	rc = difc_copy_label(&tsp->ilabel, &isp->ilabel);
	if (rc < 0)
		goto out;

	return isp;

out:
	kfree(isp);
	return NULL;
}

static int difc_cred_alloc_blank(struct cred *cred, gfp_t gfp) {
	struct task_difc *tsp;
	tsp = new_task_difc(gfp);
	if (!tsp)
		return -ENOMEM;
	
	cred->security = tsp;
	return 0;
}

static int difc_cred_prepare(struct cred *new, const struct cred *old, 
				gfp_t gfp) {
	struct task_difc *old_tsp = old->security;
	struct task_difc *new_tsp;
	int rc;

	new_tsp = new_task_difc(gfp);
	if (!new_tsp)
		return -ENOMEM;
	
	new_tsp->confined = old_tsp->confined;	
	rc = difc_copy_label(&old_tsp->slabel, &new_tsp->slabel);
	if (rc != 0)
		return rc;

	rc = difc_copy_label(&old_tsp->ilabel, &new_tsp->ilabel);
	if (rc != 0)
		return rc;

	/*
	// Don't copy ownerships
	rc = difc_copy_label(&old_tsp->olabel, &new_tsp->olabel);
	if (rc != 0)
		return rc;
	*/	

	new->security = new_tsp;
	return 0;
}

static void difc_cred_free(struct cred *cred) {
	struct task_difc *tsp = cred->security;

	if (tsp == NULL)
		return;
	cred->security = NULL;
	
	difc_free_label(&tsp->ilabel);
	list_del(&tsp->ilabel);

	difc_free_label(&tsp->slabel);
	list_del(&tsp->slabel);

	difc_free_label(&tsp->olabel);
	list_del(&tsp->olabel);

	kfree(tsp);
}


static struct security_hook_list difc_hooks[] = {
	LSM_HOOK_INIT(cred_alloc_blank, difc_cred_alloc_blank),
	LSM_HOOK_INIT(cred_free, difc_cred_free),
	LSM_HOOK_INIT(cred_prepare, difc_cred_prepare),

};

void __init difc_add_hooks(void) {
	security_add_hooks(difc_hooks, ARRAY_SIZE(difc_hooks),"ustar");
}

static __init int difc_init(void) {

	struct task_difc *tsp;
	struct cred *cred;

	tag_struct = KMEM_CACHE(tag, SLAB_PANIC);

	tsp = new_task_difc(GFP_KERNEL);
	if (!tsp)
		return -ENOMEM;

	pr_info("ustar initialization.\n");

	
	cred = (struct cred *) current->cred;
	cred->security = tsp;

	difc_add_hooks();

	return 0;
}



DEFINE_LSM(yama) = {
	.name = "ustar",
	.init = difc_init,
};
