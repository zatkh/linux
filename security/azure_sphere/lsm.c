// SPDX-License-Identifier: GPL-2.0
/*
 * Azure Sphere Linux Security Module
 *
 * Copyright (c) 2018 Microsoft Corporation. All rights reseret_valed.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 */

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

#ifdef CONFIG_EXTENDED_LSM_DIFC

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
#include <asm/udom.h>
#include "lsm.h"
#include "difc.h"


#ifdef CONFIG_EXTENDED_FLOATING_DIFC

#include "weir_lsm.h"
#include "weir_objsec.h"
#include "weir_netlink.h"

#endif

#endif /*CONFIG_EXTENDED_LSM_DIFC */


#ifdef CONFIG_EXTENDED_LSM_DIFC

static struct kmem_cache *difc_obj_kcache;
static struct kmem_cache *difc_caps_kcache;
struct kmem_cache *tag_struct;


atomic_t max_caps_num;
typedef label_t* labelList_t;
static int debug = 1;

#ifdef CONFIG_EXTENDED_FLOATING_DIFC

struct tag_list* globalpos;
struct tag_list* globalneg;

unsigned char *empty_address="0000:0000:0000:0000:0000:0000:0000:0000";

#endif


#define alloc_cap_segment() kmem_cache_zalloc(difc_caps_kcache, GFP_KERNEL)
#define free_cap_segment(s) kmem_cache_free(difc_caps_kcache, s)



#define difc_lsm_debug(fmt, arg...)					\
	do {							\
		if (debug)					\
			printk(KERN_INFO "(pid %d) %s: [%s]: " fmt ,	\
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



#ifdef CONFIG_EXTENDED_LSM

/*
struct syscall_argdesc (*seccomp_syscalls_argdesc)[] = NULL;


static const struct syscall_argdesc *__init
find_syscall_argdesc(const struct syscall_argdesc *start,
		const struct syscall_argdesc *stop, const void *addr)
{
	if (unlikely(!addr || !start || !stop)) {
		WARN_ON(1);
		return NULL;
	}

	for (; start < stop; start++) {
		if (start->addr == addr)
			return start;
	}
	return NULL;
}

static inline void __init init_argdesc(void)
{
	const struct syscall_argdesc *argdesc;
	const void *addr;
	int i;

	seccomp_syscalls_argdesc = kcalloc(NR_syscalls,
			sizeof((*seccomp_syscalls_argdesc)[0]), GFP_KERNEL);
	if (unlikely(!seccomp_syscalls_argdesc)) {
		WARN_ON(1);
		return;
	}
	for (i = 0; i < NR_syscalls; i++) {
		addr = (const void *)sys_call_table[i];
		argdesc = find_syscall_argdesc(__start_syscalls_argdesc,
				__stop_syscalls_argdesc, addr);
		if (!argdesc)
			continue;

		(*seccomp_syscalls_argdesc)[i] = *argdesc;
	}
	
}

void __init seccomp_init(void)
{
	pr_info("[seccomp_init] initializing seccomp-based sandboxing\n");
	init_argdesc();
}

*/
#endif /* CONFIG_EXTENDED_LSM */



#ifdef CONFIG_EXTENDED_FLOATING_DIFC


static struct task_security_struct *new_task_security_struct(gfp_t gfp) {
	struct task_security_struct *tsp;
	tsp = kzalloc(sizeof(struct task_security_struct), gfp);
	
	if (!tsp)
		return NULL;
	tsp->confined = false;
	INIT_LIST_HEAD(&tsp->slabel);
	INIT_LIST_HEAD(&tsp->ilabel);
	INIT_LIST_HEAD(&tsp->olabel);
	INIT_LIST_HEAD(&tsp->capList);
	INIT_LIST_HEAD(&tsp->suspendedCaps);
	tsp->tcb=FLOATING_TCB;// by default is FLOATING label task
	
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



//List shims
int add_tag(struct tag_list* orig_list, tag_t value){
	int ret = add_list(orig_list, value);
	return ret;
}
bool exists_tag(struct tag_list* orig_list, tag_t value){
	bool ret = exists_list(orig_list, value);
	return ret;
}
int remove_tag(struct tag_list* orig_list, tag_t value){
	int ret = remove_list(orig_list, value);
	return ret;
}
int copy_lists(struct tag_list* orig_list, struct tag_list* new_list){
	int ret=0;
	if(orig_list==NULL){
	    ret=-1;
	    return ret;
	}
	if(new_list==NULL){
	    ret=init_list(&new_list);
	    if(ret==ENOMEM)
		return ret;
	}
	ret=copy_list(orig_list, new_list);
	return ret;
}

//Helpers
//tag array->taglist
void get_list_from_array(tag_t *array, struct tag_list **listaddr,int size){
	int i;
	if(size<=0 || array == NULL)
	    return;
	//label should be null when initialized, else we will make it.
	if(*listaddr!=NULL) kfree(*listaddr);
	init_list(listaddr);

	for(i=0; i<size; i++){
	    add_list(*listaddr, array[i]);
	}
}
void get_list_from_array2(tag_t *array, struct tag_list *listaddr,int size){
	int i;
	if(size<=0 || array == NULL)
	    return;
	//assuming initialized list
	for(i=0; i<size; i++){
	    add_list(listaddr, array[i]);
	}
}
//taglist->tag array
tag_t* get_array_from_list(struct tag_list* taglist){
	struct list_head* pos;
	struct tag_list* tmp;
	int i=0;
	tag_t* retarray = NULL;
	int size = list_size(taglist);

	if(taglist==NULL || size <=0){
		return NULL;
	}
	
	retarray = (tag_t*)kzalloc(sizeof(tag_t) * size, GFP_KERNEL);
	//Iterate to check if "value" exists in the list
	list_for_each(pos, &(taglist->list)){
		tmp=list_entry(pos, struct tag_list, list);
		retarray[i] = tmp->t;
		i++;
	}

	return retarray;
}

//Uses the given negcaps, globalneg and given tag, and returns true 
//if the tag is present in either
bool can_declassify(tag_t tag, struct tag_list *negcaps){
    //TODO: Lock on globalneg
    if(exists_list(negcaps, tag) || exists_list(globalneg, tag)){
	return true;
    }
    return false;
}

//Populates the queryLabel with seclabel tags are not present in negcaps and
//globalneg. Returns the number of such tags, i.e., queryLabelCount.
int get_declassify_tag_list(char *queryLabel, struct tag_list *seclabel, struct
		tag_list *negcaps, int queryLabelSize)
{
    int queryLabelCount=0;	
    struct list_head* pos;
    struct tag_list* tmp;
    tag_t tag;
	
    char *cur = queryLabel, *const end = queryLabel+queryLabelSize; 
    list_for_each(pos, &(seclabel->list)){
	tmp=list_entry(pos, struct tag_list, list);
	tag = tmp->t;

	if(!can_declassify(tag, negcaps)){
	    //FIXME: Why is there a '-' after the tag? Is this for separating tags?
	    //Fix this and also make sure that the userspace knows how tags are separated
	    //FIXME: Made it '+'.
	    cur += snprintf(cur, end-cur, "%lld#", tag);
	    queryLabelCount++;
	}

	if(cur>=end)
	    break;
    }

    return queryLabelCount;
}



struct task_security_struct* get_task_security_from_task_struct_unlocked(struct task_struct* task){
    const struct cred* cred; 
    rcu_read_lock();
    cred= __task_cred(task);
    rcu_read_unlock();
    if(cred==NULL){
	//printk("WEIR: cred NULL\n");
	return NULL;
    }
    return cred->security;
}
//get task security struct from pid
struct task_security_struct* get_task_security_from_task_struct(struct task_struct* task){
    const struct cred* cred; 
    rcu_read_lock();
    cred= __task_cred(task);
    //rcu_read_unlock();
    if(cred==NULL){
	//printk("WEIR: cred NULL\n");
	return NULL;
    }
    return cred->security;
}

//get task security struct from pid
struct task_security_struct* get_task_security_from_pid(pid_t pid){
    struct task_struct* task;
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if(task==NULL){
	//printk("WEIR: task NULL for pid %d\n",pid);
	return NULL;
    }
    return get_task_security_from_task_struct(task);
}

//Add tag to the process's seclabel
void add_tag_to_label(pid_t pid, tag_t tag){
    struct task_security_struct* tsec = get_task_security_from_pid(pid);
    //struct tag_list* seclabel;

    if(tsec==NULL){
	    //printk("WEIR: tsec NULL for pid %d\n",pid);
	    goto out;
    }
    //LOCK on TSEC
    mutex_lock(&tsec->lock);
    tsec->pid = pid;
    if(tsec->seclabel==NULL){
	//printk("WEIR: Allocating tsec->seclabel for pid %d\n",pid);
	tsec->seclabel = (struct tag_list*)kzalloc(sizeof(struct tag_list), GFP_KERNEL);
	init_list2(tsec->seclabel);
    }
    add_list(tsec->seclabel, tag);
    //Release LOCK on TSEC
    mutex_unlock(&tsec->lock);
out:
    rcu_read_unlock();
    return;
}

//init process security
int init_process_security_context(pid_t pid, uid_t uid, tag_t* sec, tag_t* pos, tag_t* neg, int secsize, int possize, int negsize){
	int ret=0;
	struct task_security_struct* tsec = get_task_security_from_pid(pid);
	if(tsec==NULL){
	    //printk("WEIR: tsec is null for pid %d\n",pid);
	    ret = -1;
	    goto out;
	}

	//LOCK on TSEC
	mutex_lock(&tsec->lock);

	tsec->pid = pid;
	tsec->uid = uid;

	//For tsec->seclabel
	if(sec==NULL || secsize <=0){
	    //printk("WEIR_DEBUG: No sec suplied for %d, secsize=%d!\n", pid, secsize);
	} else {
	    //printk("WEIR_DEBUG: init_proc_security first element of sec = %lld\n", sec[0]);
	    //tsec->seclabel = (struct tag_list*)kzalloc(sizeof(struct tag_list), GFP_KERNEL);
	    //init_list2(tsec->seclabel);
	    //tsec->seclabel = get_list_from_array2(sec, tsec->seclabel, secsize);
	    get_list_from_array(sec, &(tsec->seclabel), secsize);

	}
	//For tsec->poscaps
	if(pos==NULL || possize <=0){
	    //printk("WEIR_DEBUG: No pos suplied for %d, possize=%d!\n", pid, possize);
	} else {
	    //printk("WEIR_DEBUG: init_proc_security first element of pos = %lld\n", pos[0]);
	    get_list_from_array(pos, &(tsec->poscaps), possize);
	}
	//For tsec->negcaps
	if(neg==NULL || negsize <=0){
	    //printk("WEIR_DEBUG: No neg suplied for %d, negsize=%d!\n", pid, negsize);
	} else {
	    //printk("WEIR_DEBUG: init_proc_security first element of neg = %lld\n", neg[0]);
	    get_list_from_array(neg, &(tsec->negcaps), negsize);
	}

	//Resease LOCK on TSEC
	mutex_unlock(&tsec->lock);
	//printk("WEIR: INITIALIZED SECURITY CONTEXT for pid %d, secsize %d\n",pid, secsize);
out:
	rcu_read_unlock();
	return ret;
}
  
//get label size (for ioctl)
int get_label_size(pid_t pid){
	int ret=0;
	struct task_security_struct* tsec = get_task_security_from_pid(pid);
	if(tsec==NULL){
	    //printk("WEIR: tsec is null for pid %d\n", pid);
	    ret = -1;
	    goto out;
	}
	// TODO: LOCK on TSEC; figure out why this crashes
	//mutex_lock(&tsec->lock);
	if(tsec->seclabel==NULL){
	    //printk("WEIR: tsec->seclabel is null for pid %d\n", pid);
	    ret = -1;
		//TODO: Release LOCK on TSEC
		//mutex_unlock(&tsec->lock);
	    goto out;
	}
	//printk("WEIR: tsec->seclabel is not null for pid %d\n", pid);
	ret = list_size(tsec->seclabel);
	//TODO: Release LOCK on TSEC
	//mutex_unlock(&tsec->lock);
out:
	rcu_read_unlock();
	return ret;
}
//get label
tag_t* get_label(pid_t pid){
	tag_t *ret;
	struct task_security_struct* tsec = get_task_security_from_pid(pid);
	if(tsec==NULL){
	    ret = NULL;
	    goto out;
	}

	// TODO: LOCK on TSEC; figure out why this crashes
	//mutex_lock(&tsec->lock);
	if(tsec->seclabel==NULL){
	    ret = NULL;
		//TODO: Release LOCK on TSEC
		//mutex_unlock(&tsec->lock);
	    goto out;
	}
	//printk("WEIR: tsec->seclabel is not null for pid %d\n", pid);
	ret = get_array_from_list(tsec->seclabel);
	//TODO: Release LOCK on TSEC
	//mutex_unlock(&tsec->lock);
out:
	rcu_read_unlock();
	return ret;
}

//Add/remove process pos/neg caps
void change_proccap(pid_t pid, tag_t t, int pos, int add){
	struct task_security_struct* tsec = get_task_security_from_pid(pid);
	if(tsec==NULL){
	    goto out;
	}   

	//Lock on tsec	
	mutex_lock(&tsec->lock);
    if(add==1) {//add
	    if(pos==1){//poscaps
			if(tsec->poscaps==NULL){
			    init_list(&tsec->poscaps);
			}
			add_list(tsec->poscaps, t);
	    }else if(pos==-1){//negcaps
			if(tsec->negcaps==NULL){
				init_list(&tsec->negcaps);
			}
			add_list(tsec->negcaps, t);
	    } else {}
	}
	else if(add==-1) 
	{//remove
	    if(pos==1){//poscaps
			if(tsec->poscaps==NULL){
				//Release lock on tsec
				mutex_unlock(&tsec->lock);
				goto out;
			}
			remove_list(tsec->poscaps, t);
	    }else if(pos==-1){//negcaps
			if(tsec->negcaps==NULL){
				//Release lock on tsec
				mutex_unlock(&tsec->lock);
				goto out;
			}
			remove_list(tsec->negcaps, t);
	    } else {}
	} 
	else{}

	//Release lock on tsec
	mutex_unlock(&tsec->lock);
out:
	rcu_read_unlock();
	return;


}
void change_global(tag_t t, int pos, int add){
	if(add==1) {//add
	    if(pos==1){//globalpos
		if(globalpos==NULL){
		    init_list(&globalpos);
		}
		add_list(globalpos, t);
	    }else if(pos==-1){//globalneg
		if(globalneg==NULL){
		    init_list(&globalneg);
		}
		add_list(globalneg, t);
	    } else {}
	}else if(add==-1) {//remove
	    if(pos==1){//globalpos
		if(globalpos==NULL){
		    return;
		}
		remove_list(globalpos, t);
	    }else if(pos==-1){//globalneg
		if(globalneg==NULL){
		    return;
		}
		remove_list(globalneg, t);
	    } else {}
	
	} else{}
}

/* Function that prepares the netlink upcall*/
static int send_to_uspace_pid(char* buffer) {
	//Attach the current thread's pid
	//+1 for the delimiter ';'
	char buffer_with_pid[MAX_DATA_BUFFER+sizeof(long int)+1];
	snprintf(buffer_with_pid, MAX_DATA_BUFFER+sizeof(long int)+1, "%ld;%s", (long int)(current->pid), buffer);
	return send_to_uspace(buffer_with_pid);
}

/*
 * Check if Exempted
 */
static bool exempt(int euid){
    //TODO: This exception (the <=2002 case) is for debug only. Remove it.
    if(euid==0 || euid==1000 || euid <= 2002){
	return true;
    }

    return false;
}

/*
 * Check if SDCARD
 */
static bool sdcard(int inode_gid){
    //TODO: This exception (the <=2002 case) is for debug only. Remove it.
    int SDCARD_RW=1015;
    int SDCARD_R=1028;
    if(inode_gid==SDCARD_RW || inode_gid==SDCARD_R){
	return true;
    }

    return false;
}
/*
 * Check if Exempted System apps
 */
static bool exempt_system_apps(int euid){
    //TODO: This exception (the <=2002 case) is for debug only. Remove it.
    if(euid <= 10036){
	return true;
    }

    return false;
}

/*
 * Declassification Check
 */
static int declassification_check(const char *hook, struct socket *sock, struct sockaddr *address, int addrlen)
{
    int ret = 0;

    kuid_t euid = current->cred->euid;
    //Does using the tgid make sense? We ensure that new kernel threads
    //(current->pid) have creds "prepared (copied)" from the original thread
    //(i.e., tgid == pid). Moreover, we apply new labels, tags, etc. to
    //current->pids; 
    //int pid = current->tgid;
    int pid = current->pid;
    char buffer[MAX_DATA_BUFFER];
    struct task_security_struct* tsec;
    struct tag_list *seclabel, *negcaps;
    int queryLabelSize = MAX_DATA_BUFFER/2;
    char queryLabel[queryLabelSize];
    int queryLabelCount = 0;
    //TODO: Currently gueryLabel is enough to hold ~60 tags, total 500B. Figure
    //out an optimum size

    //if(exempt(euid)){//ztodo
	//goto out;
    //}
    
    tsec = get_task_security_from_pid(pid);
    if(!tsec){
	//printk("WEIR_DEBUG: declassification_check. tsec NULL for pid %d\n",pid);
	goto out;
    }
    
    seclabel = tsec->seclabel;
    negcaps = tsec->negcaps;

    //If label == empty, allow;
    if(!seclabel || list_size(seclabel)<=0){
	//printk("WEIR_DEBUG: declassification_check. seclabel NULL or empty for pid %d\n",pid);
	goto out;
    }

    //Check if the tags in seclabel are included in globalneg or negcaps
    //If not included, add them to querylabel, separated by '-'
    queryLabelCount = get_declassify_tag_list(queryLabel, seclabel, negcaps, queryLabelSize);

    if(queryLabelCount==0){
	//declassification capability owned for all tags, allow
	goto out;
    }
    
    //Tags need to be domain-declassified; make an upcall
    if(address->sa_family==AF_INET){
	struct	sockaddr_in* temp_sockaddr;
	temp_sockaddr=(struct sockaddr_in *)address;
	if(temp_sockaddr->sin_addr.s_addr==0){
	    goto out;
	}
	//printk("Weir: socket_connectv4:%pI4;%d;%u;%d\n", &(temp_sockaddr->sin_addr), euid, pid, addrlen);
	snprintf(buffer, MAX_DATA_BUFFER, "socket%sv4;%pI4;%d;%u;%s", hook, &(temp_sockaddr->sin_addr), euid, pid, queryLabel);
	ret = send_to_uspace_pid(buffer);
    }
    else if(address->sa_family==AF_INET6){
	struct sockaddr_in6* temp_sockaddr;
	temp_sockaddr=(struct sockaddr_in6 *)address;

	//This was to check empty addresses for bind, but we aren't doing that anymore.
	/*
	 *
	unsigned char temp[71];
	snprintf(temp, 71, "%pI6", &(temp_sockaddr->sin6_addr));
	if(strcmp(temp, empty_address)==0){
	    //printk("Weir: EMPTY socket_v6:%pI6;%d;\n", &(temp_sockaddr->sin6_addr), euid);
	    goto out;
	}*/
	//printk("Weir: socket_connectv6:%pI6;%d;%u;%d\n", &(temp_sockaddr->sin6_addr), euid, pid, addrlen);
	snprintf(buffer, MAX_DATA_BUFFER, "socket%sv6;%pI6;%d;%u;%s", hook, &(temp_sockaddr->sin6_addr), euid, pid, queryLabel);
	ret = send_to_uspace_pid(buffer);
    }
    else {}

    //TODO: Remove after this
    //ret = 0;

out:
    rcu_read_unlock();
    return ret;
}

//BINDER check
static int binder_check(struct task_struct *to, struct task_struct *from){
    int ret = 0;
    kuid_t to_euid = to->cred->euid;
    kuid_t from_euid = from->cred->euid;
    //int to_pid = to->pid;
    //int from_pid = from->pid;
    struct task_security_struct *to_tsec, *from_tsec;
    struct tag_list *to_seclabel, *from_seclabel;
    //Exempt calls to and from root and system, as we handle their internal
    //state in the framework. This is to prevent system services from
    //accumulating taint.
    //printk("WEIR_DEBUG: binder_check. for (pid,uid) to:(%d,%d), from:(%d,%d).\n",to_pid, to_euid, from_pid, from_euid);

    to_tsec = get_task_security_from_task_struct_unlocked(to);
    from_tsec = get_task_security_from_task_struct_unlocked(from);

    //if(exempt(to_euid) || exempt(from_euid) || exempt_system_apps(to_euid) || exempt_system_apps(from_euid)){
	//return ret;
    //}//ztodo
    //TODO: Return -1. Apart from root which has already been exempted,
    //everyone else must have a tsec.
    if(!to_tsec || !from_tsec){
	//printk("WEIR_DEBUG: binder_check. tsec NULL for to:%d or from:%d.\n",to_pid, from_pid);
	goto out;
    }
    
    to_seclabel = to_tsec->seclabel;
    from_seclabel = from_tsec->seclabel;

    //Weir does not allow hypothetical label changes. Labels are compared as
    //is. Polyinstantiation ensures that bound instances often share the same
    //label. 
    //Since we need to assume synchronous communication, we check if both
    //labels dominate each other, i.e., are equal.
    if(!equals(to_seclabel, from_seclabel)){
	//printk("WEIR_DEBUG: binder_check. denial for (pid,uid) to:(%d,%d), from:(%d,%d).\n",to_pid, to_euid, from_pid, from_euid);
	ret = -1;
    }
out:
    //rcu_read_unlock();
    return ret;
}



int getFilePath(struct file *file, char **pathname)
{
    char *tmp;
    struct path path;
    path =file->f_path;
    path_get(&file->f_path);
    tmp = (char *)__get_free_page(GFP_KERNEL);//ztodo(GFP_TEMPORARY)
    if (!tmp) {
	return -ENOMEM;
    }
    *pathname = d_path(&path, tmp, PAGE_SIZE);
    path_put(&path);
    if (IS_ERR(*pathname)) {
	free_page((unsigned long)tmp);
	return PTR_ERR(*pathname);
    }
    free_page((unsigned long)tmp);
    return 0;
}


/*
 * Socket bind
 */
static int weir_socket_bind(struct socket *sock, struct sockaddr *address, int addrlen)
{
    int ret = 0;
    //No need to call since bind is to own address space
    //ret = declassification_check("bind", sock, address, addrlen);
    return ret;
}

/*
 * Socket Connect
 */
static int weir_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen)
{
    int ret = 0;
    ret = declassification_check("connect", sock, address, addrlen);
    return ret;
}

/* Binder Hooks
 */
static int weir_binder_set_context_mgr(struct task_struct *mgr)
{
    return 0;
}

static int weir_binder_transaction(struct task_struct *from, struct task_struct *to)
{
    return binder_check(to, from);	
}

static int weir_binder_transfer_binder(struct task_struct *from, struct task_struct *to)
{
    return binder_check(to, from);	
}

static int weir_binder_transfer_file(struct task_struct *from, struct task_struct *to, struct file *file)
{
    //As file labels are propagated during individual reads and writes, we do
    //not need to worry about the file descriptor's label right here.  Instead,
    //we just check the "to" and "from" label.	struct file_security_struct
    //*fsec = lsm_get_file(file, &selinux_ops);
    return binder_check(to, from);	
}


#endif



#ifdef CONFIG_EXTENDED_LSM_DIFC

//allocate a new label and add it to the task's cap set 
static label_t difc_alloc_label(int cap_type, int group_mode)
{

	capability_t new_cap = atomic_inc_return(&max_caps_num);
	struct cred *cred ;
	struct task_security_struct *tsec;
	struct cap_segment *cap_seg;
	int is_max=0;

	tsec = kzalloc(sizeof(struct task_security_struct), GFP_KERNEL);
	difc_lsm_debug("after kalloc\n");
  	cred = prepare_creds();
    if (!cred) {
        return -ENOMEM;
    }
    tsec = cred->security;

    if (!tsec) {
		difc_lsm_debug("not enough memory\n");
        return -ENOENT;
    }

difc_lsm_debug("after creds check\n");

	//get the requested t+ or t- cpabilty
	new_cap |= (cap_type & (PLUS_CAPABILITY| MINUS_CAPABILITY));

	if((new_cap & PLUS_CAPABILITY))
		difc_lsm_debug("allocating cap with PLUS_CAPABILITY \n");

	if((new_cap & MINUS_CAPABILITY))
		difc_lsm_debug("allocating cap with MINUS_CAPABILITY \n");

//difc_lsm_debug("before spinlock\n");
	////spin_lock(&tsec->cap_lock);

//	difc_lsm_debug("after spinlock\n");
	
	list_for_each_entry(cap_seg, &tsec->capList, list){
		if(cap_seg->caps[0] < CAP_LIST_MAX_ENTRIES){
			//difc_lsm_debug("cap_seg->caps[0]%lld \n",cap_seg->caps[0]);
			is_max = 0;
			break;
		}
	}
	if(is_max){
		cap_seg = alloc_cap_segment();
		INIT_LIST_HEAD(&cap_seg->list);
		list_add_tail(&cap_seg->list, &tsec->capList);
	}
	difc_lsm_debug("after caplist list for ech entry\n");
		
	cap_seg->caps[++(cap_seg->caps[0])] = new_cap;

//labeling mark
//	if(tsec->is_app_man)
//		tsec->tcb=APPMAN_TCB;
//	else
		tsec->tcb=REGULAR_TCB;
	difc_lsm_debug("tsec tcb %d \n",tsec->tcb);

	////spin_unlock(&tsec->cap_lock);

	// in case we want to give appman extra capabilities to declassify or etc

	//difc_lsm_debug("before commit\n");

	cred->security = tsec;
	commit_creds(cred);

	return (new_cap & CAP_LABEL_MASK);
}

// get capability of a label
static inline capability_t cred_get_capability(struct task_security_struct *tsec, label_t label)
{

	capability_t index, cap;
	struct cap_segment *cap_seg;
	list_for_each_cap(index, cap, cap_seg, tsec->capList)
		if((cap & CAP_LABEL_MASK) == label)
			return cap;

	return -1;
}

//copy user's label to kernel label_struct
static void *difc_copy_user_label(const char __user *label)
{
	int ret_val;
	void *buf;
	buf = kmalloc(sizeof(struct label_struct), GFP_KERNEL);
	if(!buf)
		return NULL;
	ret_val = copy_from_user(buf, label, sizeof(struct label_struct));
	if(ret_val){
		difc_lsm_debug(" copy failed missing bytes: %d\n", ret_val);
		kfree(buf);
		return NULL;
	}
	return buf;
}


//check if the task is labeld(or tainted)
static inline int is_task_labeled(struct task_struct *tsk)
{
	const struct cred *cred;
    struct task_security_struct *tsec;
	
    cred = get_task_cred(tsk);
    tsec = cred->security;
    if (!tsec) {
        put_cred(cred);
        return 1;
    }

	if((tsec->tcb != REGULAR_TCB) && (tsec->tcb != APPMAN_TCB))
	{
		//difc_lsm_debug("the task is not labeled \n");
		return 1;
	}

	difc_lsm_debug("this task is labeled \n");
	put_cred(cred);
	return 0;
}

int difc_check_task_labeled(struct task_struct *tsk)
{
	return is_task_labeled(tsk);

}


// add label to lables list: 
// secrecy or integrity labels are seperated via label_type 

static inline int add_label(struct label_struct *lables_list, label_t label, int label_type)
{
	label_t index, l;
	labelList_t list;

	//difc_lsm_debug("start adding %llu to the labels\n", label);
	
    switch(label_type){
	case SECRECY_LABEL: list = lables_list->sList; break;
	case INTEGRITY_LABEL: list = lables_list->iList; break;
	default: 
	  difc_lsm_debug("Invalid label, only secrecy & integrity labels are allowed\n");
	  return -EINVAL;
	}
	//check for not repeated label
	list_for_each_label(index, l, list)
	  if(label == l){
	   // difc_lsm_debug("Label already exists\n");
			return -EEXIST;
	  }
	//check the first cell for not exceeding max number of labells
	if((*list) == LABEL_LIST_MAX_ENTRIES){
	  	difc_lsm_debug("reached the max number of label entries\n");
		return -ENOMEM;
	}
    // add the lable to the list
    list[++(*list)] = label;
	difc_lsm_debug("added the label to the list\n");

	return 0;
}

// remove label from lables list: 
// secrecy or integrity labels are seperated via label_type 

static inline int remove_label(struct label_struct *lables_list, label_t label, int label_type)
{
	label_t index, l;
	labelList_t list;

	difc_lsm_debug("start removing %llu from the labels\n", label);
	
    switch(label_type){
	case SECRECY_LABEL: list = lables_list->sList; break;
	case INTEGRITY_LABEL: list = lables_list->iList; break;
	default: 
	  difc_lsm_debug("Invalid label, only secrecy & integrity labels\n");
	  return -EINVAL;
	}
	// Find the label 
	list_for_each_label(index, l, list)
		if(label == l)
			break;

	if(index > (*list)){
	  	  difc_lsm_debug("Label doesn't exist\n");
		return -ENOENT;
	}

	//shifting others after removing the label
	while(index < (*list)){
		list[index] = list[index+1];
		index++;
	}
	(*list)--;

    difc_lsm_debug("removed the label from the list\n");

	
    return 0;
}

static int __difc_set_task_label(struct task_struct *tsk, struct label_struct *lables_list, label_t label, int operation_type, int label_type, int check_only)
{

	struct cred *cred ;
	struct task_security_struct *tsec;
	capability_t cap;

	tsec = kzalloc(sizeof(struct task_security_struct), GFP_KERNEL);

	if(tsk != current)
	{
		difc_lsm_debug("can only set labels in current task credential\n");
		return -EPERM;
	}

  	cred = prepare_creds();

    if (!cred) {
		difc_lsm_debug("no cred!\n");
        return -ENOMEM;
    }
    tsec = cred->security;

    if (!tsec) {
		difc_lsm_debug("not enough memory\n");
        return -ENOENT;
    }

	//spin_lock(&tsec->cap_lock);
	cap = cred_get_capability(tsec, label); 
	//spin_unlock(&tsec->cap_lock);

	if(!cap){
		difc_lsm_debug(" Failed to find capability for %llu\n", label);
		return -EPERM;
	}

	//difc_lsm_debug("Found the capability \n");

	if(operation_type == ADD_LABEL){
		if((cap & PLUS_CAPABILITY)){
			return check_only ? 0 :  add_label(lables_list, label, label_type);
		} else  {
			difc_lsm_debug(" no PLUS_CAPABILITY for label %llu, cap %llu\n", label, cap);
			return -EPERM;
		}

	} else if(operation_type == REMOVE_LABEL)
	{
		if((cap & MINUS_CAPABILITY)){
			return check_only ? 0 : remove_label(lables_list, label, label_type);
		} else {
			difc_lsm_debug(" no MINUS_CAPABILITY for label %llu, cap %llu\n", label, cap);
			return -EPERM;
		}

	} else {
	        difc_lsm_debug(" Invalid label operation\n");
		return -EINVAL;
	}


	cred->security = tsec;
	commit_creds(cred);

}


// this checks if a label replacement is allowed 
//ZTODO: if we are gonna give appman extra declassification power, it should be checked here,for now we don't

static int check_replacing_labels_allowed(struct task_struct *tsk, struct label_struct *old_label, struct label_struct *new_label)
{

	int ret_val;
	label_t src_index, src_label, dest_index, dest_label;

 	//difc_lsm_debug("enter\n");
 	//difc_lsm_debug("new_label->sList[0]=%lld, new_label->sList[1]=%lld\n", new_label->sList[0],new_label->sList[1]);
	
	// check secrecy constraints based on the operation
	list_for_each_label(src_index, src_label, new_label->sList)
    {
		int ok = 0;
			
		list_for_each_label(dest_index, dest_label, old_label->sList)
        {
			if(src_label == dest_label)
            {
				ok = 1;
				break;
			}
		}
		if(!ok){
			if((ret_val = __difc_set_task_label(tsk, old_label, src_label, ADD_LABEL, SECRECY_LABEL, 1)) < 0)
            {
				difc_lsm_debug("Failed to add secrecy label %llu\n", src_label);
				return ret_val;
			}
		}
	}

	
	list_for_each_label(src_index, src_label, old_label->sList){

		int ok = 0;

		list_for_each_label(dest_index, dest_label, new_label->sList){
			if(src_label == dest_label)
            {
				ok = 1;
				break;
			}
		}
		if(!ok){
			if((ret_val = __difc_set_task_label(tsk, old_label, src_label, REMOVE_LABEL, SECRECY_LABEL, 1)) < 0){
				difc_lsm_debug("Failed to drop secrecy label %llu\n", src_label);
				return ret_val;
			}
		}
	}


	// the same for integrity constraint 
	list_for_each_label(src_index, src_label, new_label->iList)
    {
		int ok = 0;

		list_for_each_label(dest_index, dest_label, old_label->iList)
        {
			if(src_label == dest_label)
            {
				ok = 1;
				break;
			}
		}
		if(!ok){
			if((ret_val = __difc_set_task_label(tsk, old_label, src_label, ADD_LABEL, INTEGRITY_LABEL, 1)) < 0)
            {
				difc_lsm_debug("Failed to add integrity label %llu\n", src_label);
				return ret_val;
			}
		}
	}


	list_for_each_label(src_index, src_label, old_label->iList)
    {
		int ok = 0;
		list_for_each_label(dest_index, dest_label, new_label->iList)
        {
			if(src_label == dest_label)
            {
				ok = 1;
				break;
			}
		}
		if(!ok){
			if((ret_val = __difc_set_task_label(tsk, old_label, src_label, REMOVE_LABEL, INTEGRITY_LABEL, 1)) < 0)
            {
				difc_lsm_debug("Failed to drop integrity label %llu\n", src_label);
				return ret_val;
			}
		}
	}

	return 0;
}

static int difc_set_task_label(struct task_struct *tsk, label_t label, int operation_type, int label_type, void __user *bulk_label)
{
	int return_val;
	struct label_struct *user_label;
	struct cred *cred ;
	struct task_security_struct *tsec;


	tsec = kzalloc(sizeof(struct task_security_struct), GFP_KERNEL);

  	cred = prepare_creds();
    if (!cred) {
        return -ENOMEM;
    }
    tsec = cred->security;

    if (!tsec) {
		difc_lsm_debug("not enough memory\n");
        return -ENOENT;
    }

	//difc_lsm_debug( "operation_type: %d, label_type: %d\n",operation_type,label_type);


	if(operation_type == REPLACE_LABEL)
    {
		user_label = difc_copy_user_label(bulk_label);
		if(!user_label)
        {
		  difc_lsm_debug(" Bad user_label\n");
		  return -ENOMEM;
		}
        // check if it's ok to replace

		//difc_lsm_debug(": slist[0]=%lld, slist[1]=%lld\n", user_label->sList[0],user_label->sList[1]);
		if((return_val = check_replacing_labels_allowed(tsk, &tsec->label, user_label)) == 0)
        {
			memcpy(&tsec->label, user_label, sizeof(struct label_struct));
			//difc_lsm_debug(" replace: %lld, %lld\n", tsec->label.sList[0],tsec->label.sList[1]);

		} 
		cred->security = tsec;
	    commit_creds(cred);
		kfree(user_label);
		return return_val;
	} 
 
	//difc_lsm_debug("not a replace operation, so add/remove then %d\n", operation_type);
	return_val=__difc_set_task_label(tsk, &tsec->label, label, operation_type, label_type, 0);

	cred->security = tsec;
	commit_creds(cred);

	return return_val;
		

}

// this checks if difc constraints are ok for two labels
static int check_labaling_allowed(struct label_struct *src, struct label_struct *dest)
{

	label_t src_index, src_label, dest_index, dest_label;

	//check secrecy constraint if ok
	if(src != NULL){
		list_for_each_label(src_index, src_label, src->sList){
			int ok = 0;
			list_for_each_label(dest_index, dest_label, dest->sList){
				if(src_label == dest_label){
					ok = 1;
					break;
				}
			}
			if(!ok){
				difc_lsm_debug("failed secrecy check\n");
				//difc_lsm_debug("failed secrecy check (source label %llu != dest_label %llu)\n", src_label, dest_label);
				return -EPERM;
			}
		}
	}
	//check integrity constraint if ok
	
	if(dest != NULL){
		list_for_each_label(dest_index, dest_label, dest->iList){
			int ok = 0;
			list_for_each_label(src_index, src_label, src->iList){
				if(src_label == dest_label){
					ok = 1;
					break;
				}
			}
			if(!ok){
				difc_lsm_debug("failed integrity check\n");
				//difc_lsm_debug("failed integrity check (source label %llu != dest_label %llu)\n", src_label, dest_label);
				return -EPERM;
			}
		}
	}

	return 0;
}



// this hook can be used for comparing threads labels, for example in case of labeling domains for each thread
//ZTODO: we need to store domains labels seperatly similar to inodes using object_security_struct 
//where? probably extra security feaild in kthread_info instead of cred?

static int difc_tasks_labels_allowed(struct task_struct *s_tsk,struct task_struct *d_tsk)
{

	const struct cred *scred;
	const struct cred *rcred;
	struct task_security_struct *tsec;
	struct task_security_struct *rsec;
	int unlabeled_source_tsk, unlabeled_dest_tsk;


  	scred = get_task_cred(s_tsk);
    if (!scred) {
		difc_lsm_debug(" no cred!\n");
        return -ENOMEM;
    }
    tsec = scred->security;

    if (!tsec) {
		difc_lsm_debug(" not enough memory\n");
        return -ENOENT;
    }

  	rcred = get_task_cred(d_tsk);
    if (!rcred) {
		difc_lsm_debug(" no cred!\n");
        return -ENOMEM;
    }
    rsec = rcred->security;

    if (!rsec) {
		difc_lsm_debug(" not enough memory\n");
        return -ENOENT;
    }

	// check both tasks are labeled first
	unlabeled_source_tsk = is_task_labeled(s_tsk);
	unlabeled_dest_tsk = is_task_labeled(d_tsk);


	//no permission check required here
	if (unlabeled_source_tsk && unlabeled_dest_tsk)
		{	
			//difc_lsm_debug(" both tasks are not labeld!\n");
			return -1;
		}

	if(!unlabeled_source_tsk && !unlabeled_dest_tsk)
	{
		difc_lsm_debug(" both tasks are labeld! lets check difc allowance then\n");
		return check_labaling_allowed(&tsec->label, &rsec->label);
	}

	else
	{	
		//difc_lsm_debug(" one of the tasks is not labeld\n");
		return -1;

	}


}

	
// these two are helper funtions used for more clean way of our custome hooks to set/get inode labels without having EA support
static inline size_t inode_labels_to_buf(char *buf, size_t len, struct label_struct *isec)
{ 
	size_t ret_val = (*isec->sList) + (*isec->iList) + 2;
	size_t offset;
	ret_val *= sizeof(label_t);

	
	if(ret_val < len){// not sure having len is necessarly really!
	  difc_lsm_debug("Bad inode label %d %d\n", ret_val, len);
		return -ERANGE;
	}

	offset = ((*isec->sList) + 1) * sizeof(label_t);
	memcpy(buf, isec->sList, offset);
	memcpy(buf + offset, isec->iList, ret_val - offset);
	return ret_val;
}

static inline size_t buf_to_inode_labels(const char *buf, size_t len, struct label_struct *isec)
{ 
	label_t *lbuf = (label_t *) buf;
	size_t bound = 0;

//copy secrecy labels
	if((*lbuf) + 1 + bound > len)
	{
		difc_lsm_debug(" wrong buf len\n");
	}
	memcpy(isec->sList, buf, ((*buf) + 1) * sizeof(label_t));
	bound = (*lbuf) + 1;
	lbuf += (*lbuf) + 1;
	
// copy integrity labels
	if((*lbuf) + 1 + bound > len)
	{
		difc_lsm_debug(" wrong buf len\n");
	}
	memcpy(isec->iList, buf, ((*buf) + 1) * sizeof(label_t));
	return 0;
}

// we use the inode_get_security hook that is diffrent from inode_getsecurity hook that also used for handling EA that we don't, 
// used custome hooks to avoid conflicts
static int difc_inode_get_security(const struct inode *inode, const char *name, void *buffer, size_t size, int err)
{
	struct object_security_struct *isec = inode->i_security;
	difc_lsm_debug("getting inode sec for path %s\n", name);

	return inode_labels_to_buf(buffer, size, &isec->label);
}


static int difc_inode_set_security(struct inode *inode, const char *name,
				  const char __user *value, size_t size, int flags)
{

	struct object_security_struct *isec;
	struct label_struct *user_label;

	isec = inode->i_security;
	if(!isec) {
	  difc_lsm_debug("not enough memory\n");
		return -ENOMEM;
	}
	user_label = difc_copy_user_label(value);
	if(!user_label)
	{
		difc_lsm_debug(" Bad user_label\n");
		return -ENOMEM;
	}

	down_write(&isec->label_change_sem);


	memcpy(&isec->label, user_label, sizeof(struct label_struct));
	//difc_lsm_debug(": slist[0]=%lld, slist[1]=%lld\n", isec->label.sList[0],isec->label.sList[1]);

	up_write(&isec->label_change_sem);
	inode->i_security = isec;
	kfree(user_label);
	/* 
	struct object_security_struct *isec = inode->i_security;
	struct label_struct *user_label;

	if(!isec){
	   difc_lsm_debug("not initialzed isec\n");
	   return -EOPNOTSUPP;
	}

	user_label = difc_copy_user_label(value);
	if(!user_label)
	{
		difc_lsm_debug(" Bad user_label\n");
		return -ENOMEM;
	}

	memcpy(&isec->label, user_label, sizeof(struct label_struct));

	difc_lsm_debug(": slist[0]=%lld, slist[1]=%lld\n", user_label->sList[0],user_label->sList[1]);

	kfree(user_label);
	*/
	return 0;//buf_to_inode_labels(value, size, &isec->label);
}
static struct inode_difc *new_inode_difc(void) {
	struct inode_difc *isp;
	struct task_security_struct *tsp;
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
/*
	rc = difc_copy_label(&tsp->slabel, &isp->slabel);
	if (rc < 0)
		goto out;

	rc = difc_copy_label(&tsp->ilabel, &isp->ilabel);
	if (rc < 0)
		goto out;
*/
	return isp;

//out:
//	kfree(isp);
//	return NULL;
}

static int difc_inode_alloc_security(struct inode *inode) {
	struct inode_difc *isp;

	isp = new_inode_difc();
	if (!isp)
		return -ENOMEM;

	inode->i_security = isp;
	difc_lsm_debug("successfull inode alloc init\n");


	/*
		struct object_security_struct *isec;
	isec = kmem_cache_zalloc(difc_obj_kcache, GFP_KERNEL);
	if(!isec) {
	  difc_lsm_debug("not enough memory\n");
		return -ENOMEM;
	}

	init_rwsem(&isec->label_change_sem);
	inode->i_security = isec;
	return 0;
	*/	
	return 0;
}

static void difc_inode_free_security(struct inode *inode) {
	struct inode_difc *isp = inode->i_security;

	if (isp == NULL)
		return;
	inode->i_security = NULL;

/*	difc_free_label(&isp->ilabel);
	list_del(&isp->ilabel);

	difc_free_label(&isp->slabel);
	list_del(&isp->slabel);
*/
	kfree(isp);
	

	difc_lsm_debug("successful free");
}

static int difc_inode_init_security(struct inode *inode, struct inode *dir,
				const struct qstr *qstr, const char **name,
				void **value, size_t *len) {
	struct inode_difc *isp = inode->i_security;
	int rc, llen;
	char *labels;
	struct task_security_struct *tsp = current_security();

	
	if (!isp) {
		difc_lsm_debug("SYQ: inode->i_security is null (%s)\n", __func__);
		return 0;
	}

/*	// for now even xattr is not necessary

	if (tsp->confined) {
		difc_lsm_debug("SYQ: new inode is created %ld\n", inode->i_ino);
	}

	if (name)
		*name = XATTR_DIFC_SUFFIX;
	
	if (value && len) {
		rc = security_to_labels(&isp->slabel, &isp->ilabel, &labels, &llen);
		if (rc < 0)
			return rc;
		*value = kstrdup(labels, GFP_NOFS);
		kfree(labels);
		if (!*value) {
			difc_lsm_debug( "memory error in %s, %d\n", __func__, __LINE__);
			return -ENOMEM;
		}	
		*len = llen;
	}
*/
	return 0;
}

/*
static void difc_inode_free_security(struct inode *inode)
{
	struct object_security_struct *tsec = inode->i_security;
	inode->i_security = NULL;
	if(tsec)
		kmem_cache_free(difc_obj_kcache, tsec);

	//difc_lsm_debug("[difc_inode_free_security] successfull cleanup\n");
	
}


static int difc_inode_init_security (struct inode *inode, struct inode *dir,
				     char **name, void **value, size_t *len, 
				     void *lables_list)
{
	const struct cred *cred;
	struct object_security_struct *isec = inode->i_security;
    struct task_security_struct *tsec;
	struct label_struct *input_label = (struct label_struct *)lables_list;
	int lret;
	int rret;
	size_t labels_len;

    cred = get_task_cred(current);
    tsec = cred->security;

    if (!tsec) 
	{
        put_cred(cred);
		difc_lsm_debug(" tsec not enough memory\n");
        return -ENOMEM; // another errno later
    }

	if(!isec)
	{
		difc_lsm_debug(" isec not enough memory\n");
        return -ENOMEM;

	}

	if(input_label)
	{
		difc_lsm_debug(" inode lables_list is not empty, check if labing is allowed\n");

	 	lret = check_labaling_allowed(&tsec->label, input_label);
		rret = check_replacing_labels_allowed(current, &tsec->label, input_label);

		if((lret==0) && (rret == 0))
			memcpy(&isec->label, input_label, sizeof(struct label_struct));
		else {
			difc_lsm_debug(" Ignoring requested label on inode %lu: %d, %d\n", inode->i_ino, lret, rret);
			return -EPERM;
		}
			
	} 
	else 
		memcpy(&isec->label, &tsec->label, sizeof(struct label_struct));

	
	labels_len = (*isec->label.sList) + (*isec->label.iList);
	if(labels_len == 0)
	{
		return -EOPNOTSUPP;
	}

	//ZTODO: we are not supporing persistent label storage, but here is the place to initilaze it if we wanted to support it
	return 0;
}
*/


static int difc_inode_getsecurity(struct inode *inode,
				const char *name, void **buffer,
				bool alloc) {
	struct inode_difc *isp = inode->i_security;
	int len;
	int rc = 0;

	if (!isp) {
		difc_lsm_debug( "SYQ: inode->i_security is null (%s)\n", __func__);
		return rc; 
	}

	if (strcmp(name, XATTR_DIFC_SUFFIX) == 0) {
		rc = security_to_labels(&isp->slabel, &isp->ilabel, (char **)buffer, &len);
		if (rc < 0)
			return rc;
		else
			return len;
	}

	return rc;
}

// called by difc_inode_setxattr()
static int difc_inode_setsecurity(struct inode *inode, const char *name,
				const void *value, size_t size, int flags) {

	struct inode_difc *isp = inode->i_security;
	struct task_security_struct *tsp = current_security();
	int rc = 0;	

	if (size >= MAX_LABEL_SIZE || value ==NULL || size == 0)
		return -EINVAL;

	if (!isp) {
		difc_lsm_debug( "SYQ: inode->i_security is null (%s)\n", __func__);
		return rc; 
	}

	rc = security_set_labels(&isp->slabel, &isp->ilabel, tsp, value, size);
	if (rc < 0)
		return rc;

	return 0;
}

static int difc_inode_listsecurity(struct inode *inode, char *buffer, 
					size_t buffer_size) {
	int len = sizeof(XATTR_NAME_DIFC);
	if (buffer != NULL && len <= buffer_size)
		memcpy(buffer, XATTR_NAME_DIFC, len);
	return len;
}

static int difc_inode_getxattr(struct dentry *dentry, const char *name) {
	return 0;
}

static int difc_inode_setxattr(struct dentry *dentry, const char *name,
				const void *value, size_t size, int flags) {
	return 0;
}


static void difc_inode_post_setxattr(struct dentry *dentry, const char *name,
				const void *value, size_t size, int flags) 
{
	
	struct inode *inode = dentry->d_inode;

	difc_inode_setsecurity(inode, name, value, size, flags);
	
	return;
}

//instead of checking permissions fo each fs seperatly, we use use the inode permissions hooks
static int difc_inode_permission (struct inode *inode, int mask)
{

	const struct cred *cred ;
	struct object_security_struct *isec = inode->i_security;
	struct task_security_struct *tsec;

	int unlabeled_inode, unlabeled_task;
	int ret_val = 0;

	//difc_lsm_debug("enter\n");

  	cred = get_current_cred();
    if (!cred) {
		difc_lsm_debug(" no cred!\n");
        return -ENOMEM;
    }
    tsec = cred->security;

    if (!tsec) {
		difc_lsm_debug(" not enough memory\n");
        return -ENOENT;
    }

	if(!isec || ((*isec->label.sList) == 0 && (*isec->label.iList) == 0))
		unlabeled_inode = 1;
	else
		unlabeled_inode = 0;

	// get the current task label 
	unlabeled_task = is_task_labeled(current);

	//no permission check required here
	if (unlabeled_task && unlabeled_inode)
		return 0;

	if(unlabeled_task && !unlabeled_inode){
		//difc_lsm_debug("unlabled task want to access with mask %d, inode %lu\n", mask, inode->i_ino);
		return -1;
	}

	// check if operations are fine with the task and inode labels
	if((mask & (MAY_READ|MAY_EXEC)) != 0)
		{	
			//difc_lsm_debug(" read&exec check \n");
			ret_val |= check_labaling_allowed(&isec->label, &tsec->label);
		}

		

	if((mask & MAY_WRITE) == MAY_WRITE)
		{	
			//difc_lsm_debug(" write check \n");
			ret_val |= check_labaling_allowed(&tsec->label, &isec->label);
		}
	
	return ret_val;
}

//this hook should be used for adding new label to already existing inodes, for initialization the inode_set_lable is ok
static int difc_inode_set_label(struct inode *inode, void __user *new_label)
{
	
	struct object_security_struct *isec = inode->i_security;
	struct label_struct *user_label;
	int ret_val;

	if(!isec){
	  difc_lsm_debug("Bad isec\n");
		return -EOPNOTSUPP;
	}

	user_label = difc_copy_user_label(new_label);
	if(!user_label)
	{
		difc_lsm_debug("Bad user_label\n");
		return -ENOMEM;
	}

	down_write(&isec->label_change_sem);
	// only set new lables if based on curent task lables it is allowed
	ret_val = check_replacing_labels_allowed(current, &isec->label, user_label);

	//now check difc inode permissions for parent list as well
	if(ret_val == 0)
	{	
		struct dentry *dentry;
		struct dentry *parent;
		struct inode *p_inode;
		spin_lock(&inode->i_lock);// right locking mechanism?
		hlist_for_each_entry(dentry, &inode->i_dentry, d_u.d_alias) {

			spin_lock(&dentry->d_lock);
			parent = dentry->d_parent;
			p_inode = parent->d_inode;
		
			ret_val |= difc_inode_permission(p_inode, MAY_WRITE);

			if(ret_val)
				{
				spin_unlock(&dentry->d_lock);
				spin_unlock(&inode->i_lock);
					break;
				}
		}
		spin_unlock(&dentry->d_lock);
	} 

	spin_unlock(&inode->i_lock);

	if(ret_val == 0)
		memcpy(&isec->label, user_label, sizeof(struct label_struct));

	up_write(&isec->label_change_sem);

	difc_lsm_debug("setting new lable for the inode is done\n");
	return ret_val;
}

// difc_permanent_declassify  should be used for dropping capabilities permanently. 
// the temporarly version is used before cloning new thread instead of setting other tasks credentials that is not a good practice from securitypoint of view 
static int difc_permanent_declassify  (void __user *ucap_list, unsigned int ucap_list_size, int cap_type, int label_type)
{
	
	struct cred *cred ;
	struct task_security_struct *tsec;
	int ret_val=0;
	int found_cap = 0;
	capability_t *capList;
	capability_t temp;
	struct cap_segment *cap_seg;
	int i;
	capability_t cap;
	label_t label;
	int len;


	tsec = kzalloc(sizeof(struct task_security_struct), GFP_KERNEL);

  	cred = prepare_creds();
    if (!cred) {
        return -ENOMEM;
    }
    tsec = cred->security;

    if (!tsec) {
		difc_lsm_debug(" not enough memory\n");
        return -ENOENT;
    }

	capList = kmalloc(sizeof(capability_t) * ucap_list_size, GFP_KERNEL);
	if(!capList){
	  	difc_lsm_debug(" not enough memory\n");
		return -ENOMEM;
	}
	ret_val = copy_from_user(capList, ucap_list, sizeof(capability_t) * ucap_list_size);
	if(ret_val){
		difc_lsm_debug(" Bad copy: %d bytes missing\n", ret_val);
		kfree(capList);
		return -ENOMEM;
	}
	//spin_lock(&tsec->cap_lock);

	
	list_for_each_entry(cap_seg, &tsec->capList, list){
			if(cap_seg->caps[0] > 0){
			difc_lsm_debug("not empty caplist %lld \n",cap_seg->caps[0]);
			break;
		}
	}	

	if(label_type==SECRECY_LABEL){

		len=tsec->label.sList[0];
		for(i = 0; i < len; i++){
			label=tsec->label.sList[i+1];
			cap=cap_seg->caps[i+1];
			temp=capList[i];

			if(( temp & CAP_LABEL_MASK) == label)
			{
				difc_lsm_debug("cap[%d] matches the label \n",i+1);
				found_cap=1;
			}		

			if((cap_type & PLUS_CAPABILITY)){
				difc_lsm_debug("plus cap\n");
			}
			if((cap_type & MINUS_CAPABILITY)){			
				difc_lsm_debug("minus cap\n");}

			if(found_cap)
			{
				cap_seg->caps[i+1] = cap_seg->caps[i+2];
				(cap_seg->caps[0])--;

			}
			else{
				difc_lsm_debug("no cap\n");
				return -1;
			}

		}
	}
	else if(label_type==INTEGRITY_LABEL)
	{
		len=tsec->label.iList[0];
		for(i = 0; i < len; i++){
			label=tsec->label.iList[i+1];
			cap=cap_seg->caps[i+1];
			temp=capList[i];

			if(( temp & CAP_LABEL_MASK) == label)
			{
				difc_lsm_debug("cap[%d] matches the label \n",i+1);
				found_cap=1;
			}		

			if(found_cap)
			{
				cap_seg->caps[i+1] = cap_seg->caps[i+2];
				(cap_seg->caps[0])--;

			}
			else{
				difc_lsm_debug("no cap\n");
				return -1;
			}

		}
	}else{
		difc_lsm_debug("not vaid label_type, only secrecy and integrety support\n");
		return -1;
	}

	//spin_unlock(&tsec->cap_lock);
	cred->security = tsec;
	commit_creds(cred);

	kfree(capList);
	return ret_val;
}

// difc_temporarily_declassify stores caps in suspendedCaps that can be used before clone if we don'twant the child to inherits the capabilities 
// ZTODO: it can be merged with permanent_declassify as well

static int difc_temporarily_declassify(void __user *ucap_list, int ucap_list_size, int cap_type,int label_type)
{
	
	struct cred *cred ;
	struct task_security_struct *tsec;
	int ret_val=0;
	int found_cap = 0;
	int not_max  = 0;
	capability_t *capList;
	capability_t temp;
	struct cap_segment *cap_seg;
	struct cap_segment *sus_caps;
	int i;
	capability_t cap;
	label_t label;
	int len;

	tsec = kzalloc(sizeof(struct task_security_struct), GFP_KERNEL);

  	cred = prepare_creds();
    if (!cred) {
        return -ENOMEM;
    }
    tsec = cred->security;

    if (!tsec) {
		difc_lsm_debug(" not enough memory\n");
        return -ENOENT;
    }

	capList = kmalloc(sizeof(capability_t) * ucap_list_size, GFP_KERNEL);
	if(!capList){
	  	difc_lsm_debug(" not enough memory\n");
		return -ENOMEM;
	}
	ret_val = copy_from_user(capList, ucap_list, sizeof(capability_t) * ucap_list_size);
	if(ret_val){
		difc_lsm_debug(" Bad copy: %d bytes missing\n", ret_val);
		kfree(capList);
		return -ENOMEM;
	}
	//spin_lock(&tsec->cap_lock);

	

// drop from the main capList first but then store in suspendedCaps list

	list_for_each_entry(cap_seg, &tsec->capList, list){
			if(cap_seg->caps[0] > 0){
			difc_lsm_debug("not empty caplist %lld \n",cap_seg->caps[0]);
			break;
		}
	}	

	//difc_lsm_debug(" just checking: %lld, %lld\n", tsec->label.sList[0],tsec->label.sList[1]);
	if(label_type==SECRECY_LABEL){
		len=tsec->label.sList[0];

		for(i = 0; i < len; i++){
			label=tsec->label.sList[i+1];
			cap=cap_seg->caps[i+1];
			temp=capList[i];

			if(( cap & CAP_LABEL_MASK) == label)
			{
				difc_lsm_debug("cap[%d] matches the label \n",i+1);
			}
			if(( temp & CAP_LABEL_MASK) == label)
			{
				difc_lsm_debug("cap[%d] matches the label \n",i+1);
				found_cap=1;
			}		

			if((cap_type & PLUS_CAPABILITY)){
				difc_lsm_debug("plus cap\n");
			}
			if((cap_type & MINUS_CAPABILITY)){			
				difc_lsm_debug("minus cap\n");}

			if(found_cap)
			{
			cap_seg->caps[i+1] = cap_seg->caps[i+2];
			(cap_seg->caps[0])--;

	// store caps in the suspendedCaps list

			list_for_each_entry(sus_caps, &tsec->suspendedCaps, list){
					if(sus_caps->caps[0] < CAP_LIST_MAX_ENTRIES){
						not_max  = 1;
						break;
					}
				}
				if(!not_max ){
					sus_caps = alloc_cap_segment();
					INIT_LIST_HEAD(&sus_caps->list);
					list_add_tail(&sus_caps->list, &tsec->suspendedCaps);
				}

				sus_caps->caps[++(sus_caps->caps[0])] = temp ;

			}
			else{
				difc_lsm_debug("no cap\n");
				return -1;
			}

		}
	}
	else if(label_type==INTEGRITY_LABEL)
	{
		len=tsec->label.iList[0];
		for(i = 0; i < len; i++){
			label=tsec->label.iList[i+1];
			cap=cap_seg->caps[i+1];
			temp=capList[i];

			if(( temp & CAP_LABEL_MASK) == label)
			{
				difc_lsm_debug("cap[%d] matches the label \n",i+1);
				found_cap=1;
			}		

			if(found_cap)
			{
				cap_seg->caps[i+1] = cap_seg->caps[i+2];
				(cap_seg->caps[0])--;

	// store caps in the suspendedCaps list

			list_for_each_entry(sus_caps, &tsec->suspendedCaps, list){
					if(sus_caps->caps[0] < CAP_LIST_MAX_ENTRIES){
						not_max  = 1;
						break;
					}
				}
				if(!not_max ){
					sus_caps = alloc_cap_segment();
					INIT_LIST_HEAD(&sus_caps->list);
					list_add_tail(&sus_caps->list, &tsec->suspendedCaps);
				}

				sus_caps->caps[++(sus_caps->caps[0])] = temp ;

			}
			else{
				difc_lsm_debug("no cap\n");
				return -1;
			}

	}
	}
	else{
		difc_lsm_debug("not vaid label_type, only secrecy and integrety support\n");
		return -1;
	}
	
/* //just for debugging
	list_for_each_entry(cs, &tsec->capList, list){
			if(cs->caps[0] ==0){
		difc_lsm_debug("yep empty %lld \n",cap_seg->caps[0]);
			break;
		}
	}

	list_for_each_entry(cs2, &tsec->suspendedCaps, list){
			if(cs2->caps[0] ==1){
		difc_lsm_debug("yep added %lld \n",cs2->caps[0]);
			break;
		}
	}		
*/
	//spin_unlock(&tsec->cap_lock);
	tsec->tcb=TEMP_DCL_TCB;
	cred->security = tsec;
	commit_creds(cred);

	kfree(capList);
	return ret_val;
}

// resume the suspended capabilities
static int difc_restore_suspended_capabilities(void __user *ucap_list, unsigned int ucap_list_size, int cap_type,int label_type)
{
	
	struct cred *cred ;
	struct task_security_struct *tsec;
	int ret_val=0;
	int found_cap = 0;
	int not_max  = 0;
	capability_t *capList;
	capability_t temp;
	struct cap_segment *cap_seg;
	struct cap_segment *sus_caps;
	int i;
	capability_t cap;
	label_t label;
	int len;

	tsec = kzalloc(sizeof(struct task_security_struct), GFP_KERNEL);

  	cred = prepare_creds();
    if (!cred) {
        return -ENOMEM;
    }
    tsec = cred->security;

    if (!tsec) {
		difc_lsm_debug(" not enough memory\n");
        return -ENOENT;
    }

	capList = kmalloc(sizeof(capability_t) * ucap_list_size, GFP_KERNEL);
	if(!capList){
	  	difc_lsm_debug(" not enough memory\n");
		return -ENOMEM;
	}
	ret_val = copy_from_user(capList, ucap_list, sizeof(capability_t) * ucap_list_size);
	if(ret_val){
		difc_lsm_debug(" Bad copy: %d bytes missing\n", ret_val);
		kfree(capList);
		return -ENOMEM;
	}

	//spin_lock(&tsec->cap_lock);

// drop from the suspended capList first then restore it to main capList

	list_for_each_entry(sus_caps, &tsec->suspendedCaps, list){
			if(sus_caps->caps[0] > 0){
			difc_lsm_debug("not empty caplist %lld \n",sus_caps->caps[0]);
			break;
		}
	}	

	if(label_type==SECRECY_LABEL){

		len=tsec->label.sList[0];
		for(i = 0; i < len; i++){
			label=tsec->label.sList[i+1];
			cap=sus_caps->caps[i+1];
			temp=capList[i];

			if(( temp & CAP_LABEL_MASK) == label)
			{
				difc_lsm_debug("cap[%d] matches the label \n",i+1);
				found_cap=1;
			}		

			if(found_cap)
			{
				sus_caps->caps[i+1] = sus_caps->caps[i+2];
				(sus_caps->caps[0])--;

	// store suspended caps in the capList 

			list_for_each_entry(cap_seg, &tsec->capList, list){
					if(cap_seg->caps[0] < CAP_LIST_MAX_ENTRIES){
						not_max  = 1;
						break;
					}
				}
				if(!not_max ){
					cap_seg = alloc_cap_segment();
					INIT_LIST_HEAD(&cap_seg->list);
					list_add_tail(&cap_seg->list, &tsec->capList);
				}

				cap_seg->caps[++(cap_seg->caps[0])] = temp ;

			}
			else{
				difc_lsm_debug("no cap\n");
				return -1;
			}

		}
	}
	else if(label_type==INTEGRITY_LABEL)
	{
		len=tsec->label.iList[0];
		for(i = 0; i < len; i++){
			label=tsec->label.iList[i+1];
			cap=sus_caps->caps[i+1];
			temp=capList[i];

			if(( temp & CAP_LABEL_MASK) == label)
			{
				difc_lsm_debug("cap[%d] matches the label \n",i+1);
				found_cap=1;
			}		

			if(found_cap)
			{
				sus_caps->caps[i+1] = sus_caps->caps[i+2];
				(sus_caps->caps[0])--;

	// store suspended caps in the capList 

			list_for_each_entry(cap_seg, &tsec->capList, list){
					if(cap_seg->caps[0] < CAP_LIST_MAX_ENTRIES){
						not_max  = 1;
						break;
					}
				}
				if(!not_max ){
					cap_seg = alloc_cap_segment();
					INIT_LIST_HEAD(&cap_seg->list);
					list_add_tail(&cap_seg->list, &tsec->capList);
				}

				cap_seg->caps[++(cap_seg->caps[0])] = temp ;

			}
			else{
				difc_lsm_debug("no cap\n");
				return -1;
			}

		}
	}else{
		difc_lsm_debug("not vaid label_type, only secrecy and integrety support\n");
		return -1;
	}

	//spin_unlock(&tsec->cap_lock);
	tsec->tcb=REGULAR_TCB;
	cred->security = tsec;
	commit_creds(cred);

	kfree(capList);
	return ret_val;
}

//ZTODO: find a better way of passing caps than direct change of another task's credentials
static int difc_send_task_capabilities(pid_t pid, void __user *ucap_list, unsigned int ucap_list_size, int cap_type){


	struct cred *cred;
	const struct cred *rcred;
	struct task_security_struct *tsec;// curent cred
	struct task_security_struct *rsec;// reciver cred
	struct task_struct *dest_task = pid_task(find_vpid(pid), PIDTYPE_PID); 
	capability_t *capList;
	int ret_val=0;

	tsec = kzalloc(sizeof(struct task_security_struct), GFP_KERNEL);
	rsec = kzalloc(sizeof(struct task_security_struct), GFP_KERNEL);


  	cred = prepare_creds();
    if (!cred) {
        return -ENOMEM;
    }
    tsec = cred->security;

    if (!tsec) {
		difc_lsm_debug(" not enough memory\n");
        return -ENOENT;
    }

	rcred=get_task_cred(dest_task);
	if (!rcred) {
        return -ENOMEM;
    }
    rsec = rcred->security;

    if (!rsec) {
		difc_lsm_debug(" not enough memory\n");
        return -ENOENT;
    }

	capList = kmalloc(sizeof(capability_t) * ucap_list_size, GFP_KERNEL);
	if(!capList){
	  	difc_lsm_debug(" not enough memory\n");
		return -ENOMEM;
	}

	ret_val = copy_from_user(capList, ucap_list, sizeof(capability_t) * ucap_list_size);
	if(ret_val){
		difc_lsm_debug(" Bad copy: %d bytes missing\n", ret_val);
		kfree(capList);
		return -ENOMEM;
	}
/*	
	if(&tsec->cap_lock < &rsec->cap_lock){
		//spin_lock(&tsec->cap_lock);
		//spin_lock(&rsec->cap_lock);
	} else {
		//spin_lock(&rsec->cap_lock);
		//spin_lock(&tsec->cap_lock);
	}

	if(&tsec->cap_lock < &rsec->cap_lock){
		//spin_unlock(&rsec->cap_lock);
		//spin_unlock(&tsec->cap_lock);
	} else {
		//spin_unlock(&tsec->cap_lock);
		//spin_unlock(&rsec->cap_lock);
	}
*/


	//store the reciver task cred, current task doesn't need to be saved
	//rcred->security = rsec;
	//commit_creds(rcred);

	kfree(capList);
	return ret_val;
}

static inline const char *get_pmd_domain_name(pmd_t *pmd)
{
	switch (pmd_val(*pmd) & PMD_DOMAIN_MASK) {
	case PMD_DOMAIN(DOMAIN_KERNEL):
		return "KERNEL ";
	case PMD_DOMAIN(DOMAIN_USER):
		return "USER   ";
	case PMD_DOMAIN(DOMAIN_IO):
		return "IO     ";
	case PMD_DOMAIN(DOMAIN_VECTORS):
		return "VECTORS";
	case PMD_DOMAIN(DOMAIN_SANDBOX):
		return "SANDBOX";	
	case PMD_DOMAIN(DOMAIN_TRUSTED):
		return "TRUSTED";
	case PMD_DOMAIN(DOMAIN_UNTRUSTED):
		return "UNTRUSTED";
	default:
		return "unknown";
	}
}

static inline const char *get_pte_domain_name(pte_t *pte)
{
	switch (pte_val(*pte) & PTE_DOMAIN_MASK) {
	case PTE_DOMAIN(DOMAIN_KERNEL):
		return "KERNEL ";
	case PTE_DOMAIN(DOMAIN_USER):
		return "USER   ";
	case PTE_DOMAIN(DOMAIN_IO):
		return "IO     ";
	case PTE_DOMAIN(DOMAIN_VECTORS):
		return "VECTORS";
	case PTE_DOMAIN(DOMAIN_SANDBOX):
		return "SANDBOX";	
	case PTE_DOMAIN(DOMAIN_TRUSTED):
		return "TRUSTED";
	case PTE_DOMAIN(DOMAIN_UNTRUSTED):
		return "UNTRUSTED";
	default:
		return "unknown";
	}
}

static inline unsigned int get_pmd_domain(pmd_t *pmd)
{
	switch (pmd_val(*pmd) & PMD_DOMAIN_MASK) {
	case PMD_DOMAIN(DOMAIN_KERNEL):
		return DOMAIN_KERNEL;
	case PMD_DOMAIN(DOMAIN_USER):
		return DOMAIN_USER;
	case PMD_DOMAIN(DOMAIN_IO):
		return DOMAIN_IO;
	case PMD_DOMAIN(DOMAIN_VECTORS):
		return DOMAIN_VECTORS;
	case PMD_DOMAIN(DOMAIN_SANDBOX):
		return DOMAIN_SANDBOX;	
	case PMD_DOMAIN(DOMAIN_TRUSTED):
		return DOMAIN_TRUSTED;
	case PMD_DOMAIN(DOMAIN_UNTRUSTED):
		return DOMAIN_UNTRUSTED;
	default:
		return -1; //just for now we keep track of registerd domains 
	}
}

 
static inline void difc_set_domain(unsigned long addr, unsigned long counts, int domain)
{
    struct mm_struct *mm = current->mm;
	//unsigned long dacr = 0;
	unsigned int i;
	int domain_copy=domain;
	int unlabeled_task=1;

    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;

    spin_lock(&mm->page_table_lock);
    pgd = pgd_offset(mm, addr);
    pud = pud_offset(pgd, addr);
    pmd = pmd_offset(pud, addr);
	//ptep = pte_offset_map(pmd, addr);
	
    if (addr & SECTION_SIZE)
        pmd++;

// bits[8:5] first level entry is domain number-->0xfffffe1f
    for (i = 0; i < counts; ++i) {
		difc_lsm_debug(" pmd domain: %s\n",get_pmd_domain_name(pmd));
        *pmd = (*pmd & 0xfffffe1f) | (domain << 5);
        flush_pmd_entry(pmd);
		difc_lsm_debug(" pmd domain: %s\n",get_pmd_domain_name(pmd));

        pmd++;
    }
    spin_unlock(&mm->page_table_lock);
    difc_lsm_debug(" addr=0x%lx, counts=%ld\n", addr, counts);
	//isb();
	unlabeled_task = is_task_labeled(current);

/* 
		  __asm__ __volatile__(
            "mrc p15, 0, %[result], c3, c0, 0\n"
            : [result] "=r" (dacr) : );
    printk("dacr=0x%lx\n", dacr);
*/
	if(!unlabeled_task)
		{
			difc_lsm_debug(" task is labedl so make its domain(%d) NoAcc\n",domain);
			modify_domain(domain_copy,DOMAIN_NOACCESS);

/* 	
	__asm__ __volatile__(
    "mrc p15, 0, %[result], c3, c0, 0\n"
    : [result] "=r" (dacr) : );
    printk("dacr=0x%lx\n", dacr);

*/
		}
	else
	{
		difc_lsm_debug(" task is not labeled so its domain is in client mode\n");

	}
		

}



#endif /*CONFIG_EXTENDED_LSM_DIFC */


//btw why this is not actually setting pgid, just a dummy?
/*
static int azure_sphere_task_setpgid(struct task_struct *p, pid_t pgid)
{
    struct task_security_struct *tsec = p->cred->security;

    return 0;
}

*/


static int difc_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{

	struct task_security_struct *tsec;
	difc_lsm_debug(" difc_cred_alloc_blank\n");
	tsec = new_task_security_struct(gfp);
	if (!tsec)
		return -ENOMEM;
	
	
#ifdef CONFIG_EXTENDED_FLOATING_DIFC
mutex_init(&tsec->lock);
	tsec->pid = current->pid;
	tsec->seclabel=NULL;
	tsec->poscaps=NULL;
	tsec->negcaps=NULL;
#endif

	cred->security = tsec;
	difc_lsm_debug(" end of difc_cred_alloc_blank\n");

	return 0;

}



static void difc_cred_free(struct cred *cred) {

	struct task_security_struct *tsp=azs_cred(cred);

	if (tsp == NULL)
		return;
	cred->security = NULL;
/*	
 	if(!list_empty(&tsp->ilabel))
	{	
		difc_free_label(&tsp->ilabel);
		list_del(&tsp->ilabel);
	}

	if(!list_empty(&tsp->slabel))
	{
		difc_free_label(&tsp->slabel);
		list_del(&tsp->slabel);
	}

	if(!list_empty(&tsp->olabel))
	{
		difc_free_label(&tsp->olabel);
		list_del(&tsp->olabel);
	}
*/	
#ifdef CONFIG_EXTENDED_FLOATING_DIFC

	    mutex_lock(&tsp->lock);
	    if(tsp->seclabel!=NULL){	 kfree(tsp->seclabel);
		//printk("Freeing seclabel for pid current = %d\n", current->pid);
	    }
	    if(tsp->poscaps!=NULL)	 kfree(tsp->poscaps);
	    if(tsp->negcaps!=NULL)	 kfree(tsp->negcaps);
	    //UNLOCK TSEC (free mutex after this, before freeing tsec?)
	    mutex_unlock(&tsp->lock);

#endif

	//kfree(table);
	kfree(tsp);
}




static int difc_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp)
{
	const struct task_security_struct *old_tsec=azs_cred(old);
	struct task_security_struct *tsec=azs_cred(new);
	int rc=0;


//	if(old==NULL || new==NULL)
//	    return 0;

//	tsec = kzalloc(sizeof(struct task_security_struct), gfp);
//	tsec = new_task_security_struct(gfp);

	if (!tsec)
		return -ENOMEM;


	tsec->confined = old_tsec->confined;	
/*	rc = difc_copy_label(&old_tsec->slabel, &tsec->slabel);
	if (rc != 0)
		return rc;

	rc = difc_copy_label(&old_tsec->ilabel, &tsec->ilabel);
	if (rc != 0)
		return rc;
*/

// for floating threads we need a deep copy but for explicit one no inheritance
#ifdef CONFIG_EXTENDED_FLOATING_DIFC

	//printk("WEIR: in prepare for pid %d\n", current->pid);


	if(old_tsec==NULL){

	    mutex_init(&tsec->lock);
	    //tsec->uid = current->uid;
	    tsec->pid = current->pid;
	    tsec->seclabel=NULL;
	    tsec->poscaps=NULL;
	    tsec->negcaps=NULL;

	} else{

	    mutex_init(&tsec->lock);
	    tsec->seclabel=NULL;
	    tsec->poscaps=NULL;
	    tsec->negcaps=NULL;

	    //LOCK on OLD_TSEC
	    mutex_lock(&old_tsec->lock);
	    
	    //Commenting this as we have chosen to make deep copies.
	    //*tsec = *old_tsec;

	    tsec->pid = old_tsec->pid;
	    tsec->uid = old_tsec->uid;

	    if(old_tsec->seclabel!=NULL){
		//printk("Copying seclabel for pid current = %d old_tsec = %d\n", current->pid, old_tsec->pid);
		tsec->seclabel = (struct tag_list*)kzalloc(sizeof(struct tag_list), GFP_KERNEL);
		init_list2(tsec->seclabel);
		copy_lists(old_tsec->seclabel, tsec->seclabel);
	    }
	    if(old_tsec->poscaps!=NULL){
		tsec->poscaps = (struct tag_list*)kzalloc(sizeof(struct tag_list), GFP_KERNEL);
		init_list2(tsec->poscaps);
		copy_lists(old_tsec->poscaps, tsec->poscaps);
	    }
	    if(old_tsec->negcaps!=NULL){
		tsec->negcaps = (struct tag_list*)kzalloc(sizeof(struct tag_list), GFP_KERNEL);
		init_list2(tsec->negcaps);
		copy_lists(old_tsec->negcaps, tsec->negcaps);
	    }
    
	    mutex_unlock(&old_tsec->lock);
	}
#endif

//	*tsec = *old_tsec;
		//new->security = tsec;


	return 0;
}

static void difc_sphere_cred_transfer(struct cred *new, const struct cred *old)
{
	struct task_security_struct *old_tsec;
	struct task_security_struct *tsec;

	difc_lsm_debug("in transfer for pid %d\n", current->pid);
	if(new == NULL || old == NULL)
	    return;
	old_tsec = azs_cred(old);
	tsec = azs_cred(new);

	mutex_lock(&old_tsec->lock);
	if(old_tsec==NULL || tsec==NULL)
	    return;

	tsec->pid = old_tsec->pid;	   
	tsec->uid = old_tsec->uid;
	
	if(old_tsec->seclabel!=NULL){
	    if(tsec->seclabel == NULL){
		tsec->seclabel = (struct tag_list*)kzalloc(sizeof(struct tag_list), GFP_KERNEL);
		init_list2(tsec->seclabel);
	    }
	    copy_lists(old_tsec->seclabel, tsec->seclabel);
	}
	if(old_tsec->poscaps!=NULL){
	    if(tsec->poscaps == NULL){
		tsec->poscaps = (struct tag_list*)kzalloc(sizeof(struct tag_list), GFP_KERNEL);
		init_list2(tsec->poscaps);
	    }
	    copy_lists(old_tsec->poscaps, tsec->poscaps);
	}
	if(old_tsec->negcaps!=NULL){
	    if(tsec->negcaps == NULL){
		tsec->negcaps = (struct tag_list*)kzalloc(sizeof(struct tag_list), GFP_KERNEL);
		init_list2(tsec->negcaps);
	    }
	    copy_lists(old_tsec->negcaps, tsec->negcaps);
	}
	mutex_unlock(&old_tsec->lock);
	difc_lsm_debug("out transfer for pid %d\n", current->pid);
}

static void azure_sphere_cred_init_security(void)
{
	struct cred *cred = (struct cred *) current->real_cred;
	struct task_security_struct *tsec;
	struct cap_segment *cap_seg;
	struct cap_segment *sus_seg;



	tsec = kzalloc(sizeof(struct task_security_struct), GFP_KERNEL);
	if (!tsec)
		panic("Failed to initialize initial task security object.\n");


	//spin_lock_init(&tsec->cap_lock);

	tsec->tcb=FLOATING_TCB;


	INIT_LIST_HEAD(&tsec->capList);
	INIT_LIST_HEAD(&tsec->suspendedCaps);

	cap_seg = alloc_cap_segment();
	INIT_LIST_HEAD(&cap_seg->list);
	cap_seg->caps[0]=0;//first cell keeps the total number of caps
	list_add_tail(&cap_seg->list, &tsec->capList);

	sus_seg = alloc_cap_segment();
	INIT_LIST_HEAD(&sus_seg->list);
	sus_seg->caps[0]=0;
	list_add_tail(&sus_seg->list, &tsec->suspendedCaps);

#ifdef CONFIG_EXTENDED_FLOATING_DIFC
	tsec->pid = current->pid;
#endif

	//spin_unlock(&tsec->cap_lock);

    cred->security = tsec;


	alloc_hash();
    if (table == NULL) {
        panic("couldn't allocate udoms hash_table.\n");
 
    }

	difc_lsm_debug("[azure_sphere_cred_init_security] initialized, tsec->tcb %d\n",tsec->tcb);


}	





#ifdef CONFIG_AZURE_SPHERE_MMAP_EXEC_PROTECTION
int azure_sphere_mmap_file(struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags) {
    // if attempting write and execute at the same time then deny
    if((reqprot & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC))
        return -EPERM;

    //all good
    return 0;
}

int azure_sphere_file_mprotect(struct vm_area_struct *vma, unsigned long reqprot, unsigned long prot) {
    // if attempting write and execute at the same time then deny
    if((reqprot & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC))
        return -EPERM;

    // check the current VMA flags, if swapping between write and execute then fail
    if((vma->vm_flags & VM_WRITE) && (reqprot & PROT_EXEC)) {
        return -EPERM;
    }
    else if((vma->vm_flags & VM_EXEC) && (reqprot & PROT_WRITE)) {
        return -EPERM;
    }

    return 0;
}
#endif


#ifdef CONFIG_EXTENDED_LSM_DIFC

// allocate a new label fro one or group of threads
asmlinkage long sys_alloc_label(int type, int group_mode){

	difc_lsm_debug("enter, group_mode: %d,%d\n",type,group_mode);

	return difc_alloc_label(type,group_mode);
	//return 0;
	
}


asmlinkage long sys_permanent_declassify(void __user *ucap_list, unsigned int ucap_list_size, int cap_type,int label_type){

	difc_lsm_debug("enter\n");
	return difc_permanent_declassify(ucap_list, ucap_list_size, cap_type,label_type);
	return 0;

}

asmlinkage long sys_temporarily_declassify(void __user *ucap_list, int ucap_list_size, int cap_type,int label_type){

	difc_lsm_debug("enter %d\n",ucap_list_size);
	return difc_temporarily_declassify(ucap_list, ucap_list_size, cap_type,label_type);
	return 0;
}


asmlinkage long sys_restore_suspended_capabilities(void __user *ucap_list, unsigned int ucap_list_size, int cap_type, int label_type){

	difc_lsm_debug("enter\n");
	return difc_restore_suspended_capabilities(ucap_list, ucap_list_size, cap_type,label_type);
return 0;
}


//set current task labels
asmlinkage long sys_set_task_label(unsigned long label, int operation_type, int label_type, void *bulk_label)
{

	return difc_set_task_label(current,  label,  operation_type,  label_type, bulk_label);

}

// map an address to a specific domain
 asmlinkage int sys_set_task_domain(unsigned long addr, unsigned long counts, int domain)
 {
	//difc_lsm_debug(" enter\n");
	if(domain >= 0 && domain <16)
		{
			difc_set_domain(addr,counts, domain);
			return 0;
		}
	else {
		difc_lsm_debug("arm only supports 16 domains\n");
		return -1;
	}
	return 0;
	
}

// since this needs one thread to set credentials of another task, it's better to implement an alternative usersapce api instead
asmlinkage long sys_send_task_capabilities(pid_t pid, void __user *ucap_list, unsigned int ucap_list_size, int cap_type)
{

	difc_lsm_debug(" enter\n");
	return difc_send_task_capabilities(pid,ucap_list,ucap_list_size,cap_type);
	return 0;
}

// this tries to enter a domain that is labeld for another task. 
// can find the domain based on the target address, does not need be exact addr.
// we could ask for specific domain_id, but i think finding domains based on addr is more convinient (and possibly safe)
// we will find the doamin
asmlinkage unsigned long sys_difc_enter_domain(unsigned long addr,
        unsigned long stack, struct pt_regs *regs)
{

		difc_lsm_debug("enter \n");
		return 0;

	unsigned long dacr = 0;
	unsigned int domain;
	int domain_copy;

	int ret_val=0;
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;

	difc_lsm_debug("enter\n");
	difc_lsm_debug("pid = %d, tid = %d\n", task_tgid_vnr(current), task_pid_vnr(current));
	difc_lsm_debug("domain fault at 0x%08lx\n", addr);
	difc_lsm_debug("domain fault pc=0x%08lx, sp=0x%08lx\n", regs->ARM_pc, regs->ARM_sp);

    pgd = pgd_offset(current->mm, addr);
    pud = pud_offset(pgd, addr);
    pmd = pmd_offset(pud, addr);
    if (addr & SECTION_SIZE)
       { pmd++;}

	domain=get_pmd_domain(pmd);
	domain_copy=domain;
	if(domain<0)
		difc_lsm_debug("not registered domain\n");


	difc_lsm_debug("pmd_domain %u\n",domain);


    __asm__ __volatile__(
            "mrc p15, 0, %[result], c3, c0, 0\n"
            : [result] "=r" (dacr) : );
    printk("dacr=0x%lx\n", dacr);

	return ret_val;
	


}

asmlinkage void sys_difc_exit_domain(struct pt_regs *regs)
{
	difc_lsm_debug(" enter\n");
}

#endif /*CONFIG_EXTENDED_LSM_DIFC */


struct lsm_blob_sizes azs_blob_sizes __lsm_ro_after_init = {
	.lbs_cred = sizeof(struct task_security_struct),

};


static struct security_hook_list azure_sphere_hooks[] __lsm_ro_after_init = {

    LSM_HOOK_INIT(cred_alloc_blank, difc_cred_alloc_blank),
	LSM_HOOK_INIT(cred_free, difc_cred_free),
	LSM_HOOK_INIT(cred_prepare, difc_cred_prepare),
	LSM_HOOK_INIT(cred_transfer, difc_sphere_cred_transfer),

#ifdef CONFIG_EXTENDED_LSM_DIFC

//	LSM_HOOK_INIT(set_task_label,difc_set_task_label),
//	LSM_HOOK_INIT(copy_user_label,difc_copy_user_label),
//	LSM_HOOK_INIT(check_tasks_labels_allowed, difc_tasks_labels_allowed),
//	LSM_HOOK_INIT(check_task_labeled,difc_check_task_labeled),
	LSM_HOOK_INIT(inode_alloc_security,difc_inode_alloc_security),
	LSM_HOOK_INIT(inode_free_security,difc_inode_free_security),
	LSM_HOOK_INIT(inode_init_security,difc_inode_init_security),
	LSM_HOOK_INIT(inode_getxattr, difc_inode_getxattr),
	LSM_HOOK_INIT(inode_setxattr, difc_inode_setxattr),
	LSM_HOOK_INIT(inode_post_setxattr, difc_inode_post_setxattr),
	LSM_HOOK_INIT(inode_getsecurity, difc_inode_getsecurity),
	LSM_HOOK_INIT(inode_setsecurity, difc_inode_setsecurity),
	LSM_HOOK_INIT(inode_listsecurity, difc_inode_listsecurity),


//	LSM_HOOK_INIT(inode_label_init_security,difc_inode_init_security),
/*	LSM_HOOK_INIT(inode_get_security,difc_inode_get_security),
	LSM_HOOK_INIT(inode_set_security,difc_inode_set_security),
	LSM_HOOK_INIT(inode_set_label,difc_inode_set_label),
	LSM_HOOK_INIT(inode_permission, difc_inode_permission),


*/
#endif


};


static int __init azure_sphere_lsm_init(void)
{
	/*
    if (!security_module_enable("AzureSphere")) {
        printk(KERN_INFO "Azure Sphere LSM disabled by boot time parameter");
		return 0;
	}
	*/
	tag_struct = kmem_cache_create("difc_tag",
				  sizeof(struct tag),
				  0, SLAB_PANIC, NULL);	
	//KMEM_CACHE(tag, SLAB_PANIC);


	difc_caps_kcache = 
		kmem_cache_create("difc_cap_segment",
				  sizeof(struct cap_segment),
				  0, SLAB_PANIC, NULL);			  

	difc_obj_kcache = 
		kmem_cache_create("difc_object_struct",
				  sizeof(struct object_security_struct),
				  0, SLAB_PANIC, NULL);

	atomic_set(&max_caps_num, CAPS_INIT);

    azure_sphere_cred_init_security();

    security_add_hooks(azure_sphere_hooks, ARRAY_SIZE(azure_sphere_hooks),"AzureSphere");

    return 0;
}

//security_initcall(azure_sphere_lsm_init);


DEFINE_LSM(AzureSphere) = {
	.name = "AzureSphere",
	.blobs = &azs_blob_sizes,
	.init = azure_sphere_lsm_init,	

};
