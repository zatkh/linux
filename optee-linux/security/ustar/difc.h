#include <linux/lsm_hooks.h>
#include <linux/cred.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/difc_module.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/sched.h>

#define MAX_LABEL_SIZE 300

extern struct kmem_cache *tag_struct;

void clean_label(struct list_head *label);

int is_label_subset(struct list_head *p, 
			struct list_head *o, 
			struct list_head *q);

void change_label(struct list_head *old_label,
		struct list_head *new_label);

int can_label_change(struct list_head *old_label,
		struct list_head *new_label,
		struct list_head *olabel);

int security_to_labels(struct list_head *slabel, 
			struct list_head *ilabel, 
			char **labels, int *len);

int security_set_labels(struct list_head *slabel,
			struct list_head *ilabel,
			struct task_difc *tsp,
			const char *value, int size);
