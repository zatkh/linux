#ifndef _SECURITY_WEIR_OBJSEC_H
#define _SECURITY_WEIR_OBJSEC_H

#include <azure-sphere/security.h>


//List Functions
extern int init_list(struct tag_list** orig_list_address);
extern int init_list2(struct tag_list* orig_list_address);
extern int add_list(struct tag_list* orig_list, tag_t value);
extern int copy_list(struct tag_list* orig_list, struct tag_list* new_list);
extern bool exists_list(struct tag_list* orig_list, tag_t value);
extern int remove_list(struct tag_list* orig_list, tag_t value);
extern int list_size(struct tag_list* orig_list);
extern int list_print(struct tag_list* orig_list);
extern void union_list(struct tag_list* A, struct tag_list* B, struct tag_list** C);
extern bool dominates(struct tag_list* A, struct tag_list* B);
extern bool equals(struct tag_list* A, struct tag_list* B);
//Other Functions
/*extern int init_process_security_context(pid_t pid, uid_t uid, tag_t* sec, tag_t* pos, tag_t* neg, int secsize, int possize, int negsize);
extern int get_label_size(pid_t pid);
extern tag_t* get_label(pid_t pid);
extern void change_global(tag_t t, int pos, int add);
extern void change_proccap(pid_t pid, tag_t t, int pos, int add);
extern void add_tag_to_label(pid_t pid, tag_t t);
  
extern struct security_operations weir_ops;
*/  

#endif  /* _SECURITY_WEIR_OBJSEC_H */
