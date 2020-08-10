#ifndef _LINUX_TPT_MM_H
#define _LINUX_TPT_MM_H

#define TPT_ARRAY_SIZE 1025 /* Maximum number of smvs and memdoms allowed in a process */
#define MAIN_THREAD 0 /* Main thread is always using the first index in the metadata array: 0 */
#define LAST_RIBBON_INDEX (TPT_ARRAY_SIZE - 1)
#define LAST_MEMDOM_INDEX (TPT_ARRAY_SIZE - 1)

#include <linux/kernel.h>
#include <linux/mm_types.h>



/* Called by copy_pte_smv to locate the current pgd */
#define pgd_offset_smv(mm, address, smv_id) ((mm)->pgd_smv[smv_id]  + pgd_index((address)))

int valid_smv_fault(int smv_id, struct vm_area_struct *vma, unsigned long error_code);
int smv_tptcpy(int dst_smv, int src_smv, 
                     unsigned long addr, unsigned int flags,
                     struct vm_area_struct *vma);

#endif //_LINUX_TPT_MM_H//
