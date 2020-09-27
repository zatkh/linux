#include <linux/module.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/genetlink.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/tpt.h>
#include <linux/mdom.h>
#include <linux/sched.h>
#include "nlink.h"
#include "door.h"

struct sock *nl_sk = NULL;
struct nlmsghdr *nlh;
struct sk_buff *skb_out;

int pid;
int res;


int memdom_internal_functions(int memdom_op, long memdom_id1,
                                         long memdom_reqsize, unsigned long malloc_start, char* memdom_data, long smv_id,
                                         long memdom_priv_op, long memdom_priv_value){
    int rc = 0;
    unsigned long memdom_data_addr = 0;
    if(memdom_op == 0){        
        printk( "[%s] memdom_create()\n", __func__);
        rc = memdom_create();        
    }
    else if(memdom_op == 1){        
        printk( "[%s] memdom_kill(%ld)\n", __func__, memdom_id1);
        rc = memdom_kill(memdom_id1, NULL);        
    }
    else if(memdom_op == 2){        
        printk(KERN_INFO "[%s] memdom_mmap_register(%ld)\n", __func__, memdom_id1);
        rc = memdom_mmap_register(memdom_id1);
    }
    else if(memdom_op == 3){

        rc = kstrtoul(memdom_data, 10, &memdom_data_addr);
          if (rc) {
              printk("[%s] Error: convert memdom_data address to unsigned long failed, returned %d\n", __func__, rc);
          }
          printk("[%s] memdom_munmap(%ld, 0x%08lx)\n", __func__, memdom_id1, memdom_data_addr);
        rc = memdom_munmap(memdom_data_addr);
    }
    else if(memdom_op == 4){      
        if(memdom_priv_op == 0){            
            printk(KERN_INFO "[%s] memdom_priv_get(%ld, %ld)\n", __func__, memdom_id1, smv_id);
            rc = memdom_priv_get(memdom_id1, smv_id);            
        }        
        else if(memdom_priv_op == 1){            
            printk(KERN_INFO "[%s] memdom_priv_add(%ld, %ld, %ld)\n", __func__, memdom_id1, smv_id, memdom_priv_value);
            rc = memdom_priv_add(memdom_id1, smv_id, memdom_priv_value);            
        }        
        else if(memdom_priv_op == 2){            
            printk(KERN_INFO "[%s] memdom_priv_del(%ld, %ld, %ld)\n", __func__, memdom_id1, smv_id, memdom_priv_value);
            rc = memdom_priv_del(memdom_id1, smv_id, memdom_priv_value);            
        }        
    }

    return rc;
}


int tpt_internal_functions(int tpt_op, long smv_id, int smv_domain_op,
                                          long memdom_id1, long memdom_id2){
    
    int rc = 0;

    if(tpt_op == 0){
        printk( "[%s] smv_create()\n", __func__);
        rc = smv_create();
    }else if(tpt_op == 1){
        printk( "[%s] smv_kill(%ld)\n", __func__, smv_id);
        rc = smv_kill(smv_id, NULL);
    }else if(tpt_op == 2){
        printk( "[%s] smv_run(%ld)\n", __func__, smv_id);
    }else if(tpt_op == 3){
        if(smv_domain_op == 0){
            printk( "[%s] smv_join_domain(%ld, %ld)\n", __func__, memdom_id1, smv_id);
            rc = smv_attach_mdom(memdom_id1, smv_id);
        }else if(smv_domain_op == 1){
            printk( "[%s] smv_leave_domain(%ld, %ld)\n", __func__, smv_id, memdom_id1);
            rc = smv_leave_mdom(memdom_id1, smv_id, NULL);
        }else if(smv_domain_op == 2){
            printk("[%s] smv_is_in_domain(%ld, %ld)\n", __func__, memdom_id1, smv_id);
            rc = is_smv_joined_mdom(memdom_id1, smv_id);
        }
    }
    return rc;
}



    
int parse_message(char* message){
    char **buf;
    char *token;
    int message_type = -1;      /* message type: 0: memdom, 1: smv, -1: undefined */
    int memdom_op = -1;         /* 0: create, 1: kill, 2: mmap, 3: unmap, 4: priv, -1: undefined */
    long memdom_priv_op = -1;    /* 0: get, 1: add, 2: del, 3: mod, -1: undefined */
    long memdom_priv_value = -1;
    long memdom_id1 = -1;
    long memdom_id2 = -1;
    long memdom_nbytes = -1;
    void *memdom_data = NULL;
    unsigned long malloc_start = 0;

    int tpt_op = -1;         /* 0: create, 1: kill, 2: run, 3: domain related, -1: undefined */
    int smv_domain_op = -1;    /* 0: join, 1: leave, 2: isin, 3: switch, -1: undefined */
    long smv_id = -1;

    int i = 0;

    printk(KERN_INFO "parsing: %s\n", message);

    if(message == NULL)
        return 0;
    buf = &message;


    while( (token = strsep(buf, ",")) ){

        i++;

        if(message_type == -1){
            if( (strcmp(token, "memdom")) == 0)
                message_type = 0;
            else if( (strcmp(token, "smv")) == 0)
                message_type = 1;
            else if( (strcmp(token, "door")) == 0)
                message_type = 2;    
            else if( (strcmp(token, "gdb_breakpoint")) == 0){
                message_type = 9;
                break;
            }
            
            continue;
        }
        
        // decide operation

        if(message_type ==2)
        {
            printk(KERN_INFO "door ops: %s\n");
            if( (strcmp(token, "open")) == 0 )
               door_internal_functions(0,0,0);
            else if( (strcmp(token, "close")) == 0 )
                door_internal_functions(1,0,0);
             else if( (strcmp(token, "call")) == 0 )
               door_internal_functions(2,0,0);



        }
        else if( message_type == 0 && memdom_op == -1){  // memdom
            printk(KERN_INFO "memdom token 2 (op): %s\n", token);

            if( (strcmp(token, "create")) == 0 )
                memdom_op = 0;
            else if( (strcmp(token, "kill")) == 0 )
                memdom_op = 1;
            else if( (strcmp(token, "mmapregister")) == 0 )
                memdom_op = 2;
            else if( (strcmp(token, "munmap")) == 0 )
                memdom_op = 3;
            else if( (strcmp(token, "priv")) == 0 )
                memdom_op = 4;
            else if( (strcmp(token, "queryid")) == 0 )
                memdom_op = 5;
            else if( (strcmp(token, "privateid")) == 0 )
                return memdom_private_id();
            else if( (strcmp(token, "mainid")) == 0 )
                /* Return the global memdom id used by the main thread*/
                return memdom_main_id();
            else if( (strcmp(token, "dumppgtable")) == 0) 
                memdom_op = 9;
            else {
                printk(KERN_INFO "Error: received undefined memdom ops: %s\n", token);
                return -1;
            }
            continue;
        }
        else if( message_type == 1 && tpt_op == -1){ // smv
            printk(KERN_INFO "smv token 2 (op): %s\n", token);
            if( (strcmp(token, "create")) == 0 )
                tpt_op = 0;
            else if( (strcmp(token, "kill")) == 0 )
                tpt_op = 1;
            else if( (strcmp(token, "run")) == 0 )
                tpt_op = 2;
            else if( (strcmp(token, "domain")) == 0 )
                tpt_op = 3;
            else if ((strcmp(token, "exists")) == 0 ) 
                tpt_op = 4; // print all vma a smv holds
            else if ((strcmp(token, "registerthread")) == 0 ) 
                tpt_op = 5;
            else if ((strcmp(token, "printpgtable")) == 0) 
                tpt_op = 6; //get smv id            
            else if ((strcmp(token, "finalize")) == 0) 
                tpt_op = 7; //finalize smv environment            
            else if ((strcmp(token, "maininit")) == 0 ) 
                tpt_op = 9;
            else if ((strcmp(token, "getsmvid")) == 0) 
                tpt_op = 10; //get smv id
            else {
                printk(KERN_INFO "Error: received undefined smv ops: %s\n", token);
                return -1;
            }
            continue;
        }
        
        /* token 3 */
        // memdom: get memdom id
        if( message_type == 0 && (memdom_op >= 1 && memdom_op <=4) && memdom_id1 == -1 ){
            printk(KERN_INFO "memdom token 3 (memdom_id): %s\n", token);
            if( kstrtol(token, 10, &memdom_id1) ){
                return -1;
            }
            continue;
        }
        // memdom: get query addr
        else if( message_type == 0 && memdom_op == 5 ){
            unsigned long address = 0;
            printk(KERN_INFO "memdom token 3 (addr): %s\n", token);
            if( kstrtoul(token, 10, &address) ){
                return -1;
            }
            printk(KERN_INFO "addr: 0x%16lx\n", address);
            return memdom_query_id(address);
        }
        
        // smv: get smv id
        else if( message_type == 1 && (tpt_op >= 1 || tpt_op <= 6) && smv_id == -1){
            printk(KERN_INFO "memdom token 3 (smv_id): %s\n", token);
            if( kstrtol(token, 10, &smv_id) ){
                return -1;
            }
            continue;
        }
        
        /* token 4*/
        // memdom
        if( message_type == 0 && (memdom_nbytes == -1 && memdom_data == NULL && smv_id == -1)){
            printk(KERN_INFO "memdom token 4: %s\n", token);

            // memdom allocate, get nbytes
            // deprecated, implemented in user space library
            if( memdom_op == 2){
//              if( kstrtol(token, 10, &memdom_nbytes) )
//                  return -1;
            }
            // memdom munmap, get *data
            else if( memdom_op == 3){
//              memdom_data = token;
            }
            // memdom priv, get smvID
            if( memdom_op == 4){
                if( kstrtol(token, 10, &smv_id) )
                    return -1;
            }
            continue;
        }
        // smv gets memory domain op
        else if( message_type == 1 && tpt_op == 3 && smv_domain_op == -1){
            if( (strcmp(token, "join")) == 0)
                smv_domain_op = 0;
            else if( (strcmp(token, "leave")) == 0)
                smv_domain_op = 1;
            else if( (strcmp(token, "isin")) == 0)
                smv_domain_op = 2;
            else if( (strcmp(token, "switch")) == 0)
                smv_domain_op = 3;
            else {
                printk(KERN_INFO "Error: received undefined smv domain ops: %s\n", token);
                return -1;
            }
            continue;
        }
        
        /* token 5 */
        // memdom
        if(message_type == 0){
            /* Get memdom privilege operations */
            if(memdom_op == 4 && memdom_priv_op == -1){
                printk(KERN_INFO "memdom token 5 (memdom_priv_op): %s\n", token);

                if( (strcmp(token, "get")) == 0)
                    memdom_priv_op = 0;
                else if( (strcmp(token, "add")) == 0)
                    memdom_priv_op = 1;
                else if( (strcmp(token, "del")) == 0)
                    memdom_priv_op = 2;
                else if( (strcmp(token, "mod")) == 0)
                    memdom_priv_op = 3;
                else{
                    printk(KERN_INFO "Error: received undefined memdom priv ops: %s\n", token);
                    return -1;
                }
                continue;           
            }
            /* Get the starting address of malloced memory block*/
            else if (memdom_op == 2 && malloc_start == 0) {
                printk(KERN_INFO "memdom token 5 (starting address of malloced memory block): %s\n", token);
                if(kstrtoul(token, 10, &malloc_start)){
                    printk(KERN_INFO "Error: failed to convert malloc addr: %lu\n", malloc_start);
                    return -1;
                }
                continue;           
            }

        }
            // smv gets memory domain id
        else if(message_type == 1 && tpt_op == 3 && memdom_id1 == -1){
            printk(KERN_INFO "smv gets memdom_id1: %s\n", token);
            if( kstrtol(token, 10, &memdom_id1) )
                return -1;
            continue;
        }
        
        
        /* token 6*/
        // memdom gets memdom privilege value 
        if( message_type == 0 && smv_id != -1 && memdom_priv_op != -1 && memdom_priv_value == -1){
            printk(KERN_INFO "memdom token 6 (memdom_priv_value): %s\n", token);

            if( kstrtol(token, 10, &memdom_priv_value) ){
                printk(KERN_INFO "Error: received undefined memdom priv value: %s\n", token);
                return -1;
            }
            continue;
        }
        // smv gets 2nd memory domain id
        else if( message_type == 1 && memdom_id1 != -1 && memdom_id2 == -1){
            printk(KERN_INFO "smv gets memdom_id2: %s\n", token);
            if( kstrtol(token, 10, &memdom_id2) )
                return -1;
            continue;
        }
    }
    
    if(message_type == 0){
        if (memdom_op == 9) {
//          page_walk_by_task(NULL);
            return 0;
        }
        else{
            return memdom_internal_functions(memdom_op, memdom_id1, 
                                                memdom_nbytes, malloc_start, memdom_data, smv_id,
                                                memdom_priv_op, memdom_priv_value);
        }
    }
    else if(message_type == 1){

        if (tpt_op == 10) {
            /* User queries smv ID the current thread is running in */
            return get_curr_smv_id();
        }
        else if (tpt_op == 9) {
            smv_main_init();
            return 0;
        }
        else if (tpt_op == 7) {
            printk(KERN_INFO "[%s] empty op\n", __func__);
        } 
        else if (tpt_op == 4) {
            /* Check whether a smv exists */
            return smv_exists(smv_id);
        } 
        else if (tpt_op == 5) {
            printk(KERN_INFO "[%s] register smv thread running in smv %ld\n", __func__, smv_id);
            register_smv_thread(smv_id);
            return 0;
        } 
        else if (tpt_op == 6) {
            printk(KERN_INFO "[%s] empty op\n", __func__);
//          smv_print_pgtables(smv_id);
            return 0;
        } 
        else {
            /* Other smv operations */
            return tpt_internal_functions(tpt_op, smv_id, smv_domain_op, 
                                                 memdom_id1, memdom_id2);
        }

    }else if(message_type == 9){
//      kernel_gdb_breakpoint();
        return 0;
    }

    
   printk(KERN_DEBUG "[%s] unknown message: %s\n", __func__, message);
    
    return -1;
    
}

static void recv_msg(struct sk_buff *skb) {
    printk(KERN_INFO "Entering: %s\n", __FUNCTION__);
    nlh = (struct nlmsghdr*)skb->data;
    char buf[50];
    int msg_size;


   int ret= parse_message((char*)nlmsg_data(nlh));
   if(ret ==-1)
      { printk(KERN_INFO "parse msg failed:%s\n",(char*)nlmsg_data(nlh));}

    else
    {
        sprintf(buf, "%d", ret);
        msg_size = strlen(buf);
    }
    
    printk(KERN_INFO "Netlink after parsing received msg payload:%s\n",(char*)nlmsg_data(nlh));

    pid = nlh->nlmsg_pid;
    printk(KERN_INFO "PID: %i\n", pid);

    skb_out = nlmsg_new(msg_size, 0);

    if(!skb_out)
    {
        printk(KERN_ERR "Failed to allocate new skb\n");

        return;
    }

    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    NETLINK_CB(skb_out).dst_group = (1 << 3); /* mcast group */
    strncpy(nlmsg_data(nlh), buf, msg_size);

    res = nlmsg_unicast(nl_sk, skb_out, pid);

    if(res<0) {
        printk(KERN_INFO "Error while sending bak to user\n");
    }
}

static int __init init(void) {
    printk("[tpt] initializing: %s\n",__FUNCTION__);

    struct netlink_kernel_cfg cfg = {
        .input = recv_msg,
    };

    nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
    if(!nl_sk)
    {
        printk(KERN_ALERT "Error creating socket.\n");
        return -10;
    }

    return 0;
}

static void __exit exit(void) {
    printk(KERN_INFO "exiting hello module\n");
    netlink_kernel_release(nl_sk);
}

module_init(init); module_exit(exit);

MODULE_LICENSE("GPL");
