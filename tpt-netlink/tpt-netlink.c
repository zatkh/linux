#include <net/genetlink.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/tpt.h>
#include <linux/mdom.h>
#include <linux/sched.h>

/* attributes (variables): the index in this enum is used as a reference for the type,
 *             userspace application has to indicate the corresponding type
 *             the policy is used for security considerations
 */

enum {
	DOC_EXMPL_A_UNSPEC,
	DOC_EXMPL_A_MSG,
    __DOC_EXMPL_A_MAX,
};
#define DOC_EXMPL_A_MAX (__DOC_EXMPL_A_MAX - 1)

/* attribute policy: defines which attribute has which type (e.g int, char * etc)
 * possible values defined in net/netlink.h
 */
static struct nla_policy doc_exmpl_genl_policy[DOC_EXMPL_A_MAX + 1] = {
	[DOC_EXMPL_A_MSG] = { .type = NLA_NUL_STRING },
};

#define VERSION_NR 1
/* family definition */
static struct genl_family tpt_gnl_family = {
	.hdrsize = 0,
	.name = "CONTROL_EXMPL",        //the name of this family, used by userspace application
	.version = VERSION_NR,                   //version number
	.maxattr = DOC_EXMPL_A_MAX,
};

/* commands: enumeration of all commands (functions),
 * used by userspace application to identify command to be ececuted
 */
enum {
	DOC_EXMPL_C_UNSPEC,
	DOC_EXMPL_C_ECHO,
	__DOC_EXMPL_C_MAX,
};
#define DOC_EXMPL_C_MAX (__DOC_EXMPL_C_MAX - 1)

int memdom_internal_functions(int memdom_op, long memdom_id1,
                                         long memdom_reqsize, unsigned long malloc_start, char* memdom_data, long smv_id,
                                         long memdom_priv_op, long memdom_priv_value){
    int rc = 0;
    unsigned long memdom_data_addr = 0;
    if(memdom_op == 0){        
        tpt_debug("memdom_create()\n");
        rc = memdom_create();        
    }
    else if(memdom_op == 1){        
        tpt_debug( "memdom_kill(%ld)\n", memdom_id1);
        rc = memdom_kill(memdom_id1, NULL);        
    }
    else if(memdom_op == 2){        
        tpt_debug( " memdom_mmap_register(%ld)\n", memdom_id1);
        rc = memdom_mmap_register(memdom_id1);
    }
    else if(memdom_op == 3){

        rc = kstrtoul(memdom_data, 10, &memdom_data_addr);
          if (rc) {
              tpt_debug("Error: convert memdom_data address to unsigned long failed, returned %d\n",  rc);
          }
          tpt_debug("memdom_munmap(%ld, 0x%08lx)\n",  memdom_id1, memdom_data_addr);
        rc = memdom_munmap(memdom_data_addr);
    }
    else if(memdom_op == 4){      
        if(memdom_priv_op == 0){            
            tpt_debug( "memdom_priv_get(%ld, %ld)\n",  memdom_id1, smv_id);
            rc = memdom_priv_get(memdom_id1, smv_id);            
        }        
        else if(memdom_priv_op == 1){            
            tpt_debug( "memdom_priv_add(%ld, %ld, %ld)\n",  memdom_id1, smv_id, memdom_priv_value);
            rc = memdom_priv_add(memdom_id1, smv_id, memdom_priv_value);            
        }        
        else if(memdom_priv_op == 2){            
            tpt_debug( "memdom_priv_del(%ld, %ld, %ld)\n",  memdom_id1, smv_id, memdom_priv_value);
            rc = memdom_priv_del(memdom_id1, smv_id, memdom_priv_value);            
        }        
    }

    return rc;
}

int tpt_internal_functions(int tpt_op, long smv_id, int smv_domain_op,
                                          long memdom_id1, long memdom_id2){
    
    int rc = 0;

    if(tpt_op == 0){
        tpt_debug( "smv_create()\n");
        rc = smv_create();
    }else if(tpt_op == 1){
        tpt_debug( "smv_kill(%ld)\n",  smv_id);
        rc = smv_kill(smv_id, NULL);
    }else if(tpt_op == 2){
        tpt_debug( "smv_run(%ld)\n",  smv_id);
    }else if(tpt_op == 3){
        if(smv_domain_op == 0){
            tpt_debug( "smv_join_domain(%ld, %ld)\n",  memdom_id1, smv_id);
            rc = smv_attach_mdom(memdom_id1, smv_id);
        }else if(smv_domain_op == 1){
            tpt_debug( "smv_leave_domain(%ld, %ld)\n",  smv_id, memdom_id1);
            rc = smv_leave_mdom(memdom_id1, smv_id, NULL);
        }else if(smv_domain_op == 2){
            tpt_debug("smv_is_in_domain(%ld, %ld)\n",  memdom_id1, smv_id);
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

    if(message == NULL)
        return 0;
    buf = &message;

    tpt_debug( "parsing: %s\n", message);

    while( (token = strsep(buf, ",")) ){

        i++;
//        tpt_debug("token %d = %s\n", i, token);
        
        /* token 1 */
        // decide message type
        if(message_type == -1){
            if( (strcmp(token, "memdom")) == 0)
                message_type = 0;
            else if( (strcmp(token, "smv")) == 0)
                message_type = 1;
            else if( (strcmp(token, "gdb_breakpoint")) == 0){
                message_type = 9;
                break;
            }
            
            continue;
        }
        
        /* token 2 */
        // decide operation
        if( message_type == 0 && memdom_op == -1){  // memdom
            tpt_debug( "memdom token 2 (op): %s\n", token);

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
                tpt_debug( "Error: received undefined memdom ops: %s\n", token);
                return -1;
            }
            continue;
        }
        else if( message_type == 1 && tpt_op == -1){ // smv
            tpt_debug( "smv token 2 (op): %s\n", token);
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
                tpt_debug( "Error: received undefined smv ops: %s\n", token);
                return -1;
            }
            continue;
        }
        
        /* token 3 */
        // memdom: get memdom id
        if( message_type == 0 && (memdom_op >= 1 && memdom_op <=4) && memdom_id1 == -1 ){
            tpt_debug( "memdom token 3 (memdom_id): %s\n", token);
            if( kstrtol(token, 10, &memdom_id1) ){
                return -1;
            }
            continue;
        }
        // memdom: get query addr
        else if( message_type == 0 && memdom_op == 5 ){
            unsigned long address = 0;
            tpt_debug( "memdom token 3 (addr): %s\n", token);
            if( kstrtoul(token, 10, &address) ){
                return -1;
            }
            tpt_debug( "addr: 0x%16lx\n", address);
            return memdom_query_id(address);
        }
        
        // smv: get smv id
        else if( message_type == 1 && (tpt_op >= 1 || tpt_op <= 6) && smv_id == -1){
            tpt_debug( "memdom token 3 (smv_id): %s\n", token);
            if( kstrtol(token, 10, &smv_id) ){
                return -1;
            }
            continue;
        }
        
        /* token 4*/
        // memdom
        if( message_type == 0 && (memdom_nbytes == -1 && memdom_data == NULL && smv_id == -1)){
            tpt_debug( "memdom token 4: %s\n", token);

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
                tpt_debug( "Error: received undefined smv domain ops: %s\n", token);
                return -1;
            }
            continue;
        }
        
        /* token 5 */
        // memdom
        if(message_type == 0){
            /* Get memdom privilege operations */
            if(memdom_op == 4 && memdom_priv_op == -1){
                tpt_debug( "memdom token 5 (memdom_priv_op): %s\n", token);

                if( (strcmp(token, "get")) == 0)
                    memdom_priv_op = 0;
                else if( (strcmp(token, "add")) == 0)
                    memdom_priv_op = 1;
                else if( (strcmp(token, "del")) == 0)
                    memdom_priv_op = 2;
                else if( (strcmp(token, "mod")) == 0)
                    memdom_priv_op = 3;
                else{
                    tpt_debug( "Error: received undefined memdom priv ops: %s\n", token);
                    return -1;
                }
                continue;           
            }
            /* Get the starting address of malloced memory block*/
            else if (memdom_op == 2 && malloc_start == 0) {
                tpt_debug( "memdom token 5 (starting address of malloced memory block): %s\n", token);
                if(kstrtoul(token, 10, &malloc_start)){
                    tpt_debug( "Error: failed to convert malloc addr: %lu\n", malloc_start);
                    return -1;
                }
                continue;           
            }

        }
            // smv gets memory domain id
        else if(message_type == 1 && tpt_op == 3 && memdom_id1 == -1){
            tpt_debug( "smv gets memdom_id1: %s\n", token);
            if( kstrtol(token, 10, &memdom_id1) )
                return -1;
            continue;
        }
        
        
        /* token 6*/
        // memdom gets memdom privilege value 
        if( message_type == 0 && smv_id != -1 && memdom_priv_op != -1 && memdom_priv_value == -1){
            tpt_debug( "memdom token 6 (memdom_priv_value): %s\n", token);

            if( kstrtol(token, 10, &memdom_priv_value) ){
                tpt_debug( "Error: received undefined memdom priv value: %s\n", token);
                return -1;
            }
            continue;
        }
        // smv gets 2nd memory domain id
        else if( message_type == 1 && memdom_id1 != -1 && memdom_id2 == -1){
            tpt_debug( "smv gets memdom_id2: %s\n", token);
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
            tpt_debug( "empty op\n");
        } 
        else if (tpt_op == 4) {
            /* Check whether a smv exists */
            return smv_exists(smv_id);
        } 
        else if (tpt_op == 5) {
            tpt_debug( "register smv thread running in smv %ld\n",  smv_id);
            register_smv_thread(smv_id);
            return 0;
        } 
        else if (tpt_op == 6) {
            tpt_debug( "empty op\n");
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

    
//    tpt_debug(KERN_DEBUG "unknown message: %s\n",  message);
    
    return -1;
    
}

// the main msg handler: receives a message, parse it and sends the results back
int main_handler(struct sk_buff *skb_2,  struct genl_info *info)
{
    struct nlattr *na;
    struct sk_buff *skb;
    int rc;
	void *msg_head;
	char * mydata = NULL;
	int result;
    char buf[50];
    
    if (info == NULL)
        goto out;
    
    /*for each attribute there is an index in info->attrs which points to a nlattr structure
     *in this structure the data is given
     */
    na = info->attrs[DOC_EXMPL_A_MSG];
    if (na) {
		mydata = (char *)nla_data(na);
		if (mydata == NULL)
			tpt_debug(KERN_ERR "[smv_netlink.c] error while receiving data\n");
    }
	else
		tpt_debug( "no info->attrs %i\n", DOC_EXMPL_A_MSG);
    
    /* Parse the received message here */
    result = parse_message(mydata);
    
    /* send a message back*/
    /* allocate some memory, since the size is not yet known use NLMSG_GOODSIZE*/
    skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (skb == NULL)
		goto out;
    
	/* create the message headers */

    msg_head = genlmsg_put(skb, 0, info->snd_seq+1, &tpt_gnl_family, 0, DOC_EXMPL_C_ECHO);
	if (msg_head == NULL) {
		rc = -ENOMEM;
		goto out;
	}
	/* add a DOC_EXMPL_A_MSG attribute (actual value to be sent) */
    sprintf(buf, "%d", result);
	rc = nla_put_string(skb, DOC_EXMPL_A_MSG, buf);
	if (rc != 0)
		goto out;
	
    /* finalize the message */
	genlmsg_end(skb, msg_head);
    
    /* send the message back */
    rc = genlmsg_unicast(genl_info_net(info), skb, info->snd_portid);
	if (rc != 0)
		goto out;
	return 0;
    
out:
    tpt_debug("an error occured in main_handler:\n");
    
    return 0;
}
/* commands: mapping between the command enumeration and the actual function*/
static const struct genl_ops doc_exmpl_gnl_ops_echo[] = {
    {
    	.cmd = DOC_EXMPL_C_ECHO,
  	    .flags = 0,
    	.policy = doc_exmpl_genl_policy,
	    .doit = main_handler,
    },
};

static int __init kernel_comm_init(void)
{
	int rc;
    tpt_debug( "[tpt] initializing the module\n");

    rc = genl_register_family(&tpt_gnl_family);
	if (rc != 0){
        tpt_debug("register ops: %i\n",rc);
        genl_unregister_family(&tpt_gnl_family);
		goto failure;
    }    
	return 0;
	
failure:
    tpt_debug( "[tpt] error occured while inserting the netlink module\n");
	return -1;	
}

static void __exit kernel_comm_exit(void)
{
    int ret;
    tpt_debug( "[tpt] KERNEL COMMUNICATION MODULE EXIT\n");

    /*unregister the family*/
	ret = genl_unregister_family(&tpt_gnl_family);
	if(ret !=0){
        tpt_debug("unregister family %i\n",ret);
    }
}


module_init(kernel_comm_init);
module_exit(kernel_comm_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Main component for user space API to communicate with the kernel.");
 


