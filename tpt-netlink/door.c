#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/file.h>
#include <linux/limits.h>
#include <linux/mount.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <linux/blkdev.h>


#include <asm/uaccess.h>
#include <asm/string.h>
#include <asm/mmu_context.h>
#include <asm/hardirq.h>
#include "door.h"


#define DOOR_DEBUG

#define HFORMAT( function, format, args... )			\
    ( function )( "door[%i]: %s (%i) " format "\n" ,		\
              in_interrupt() || in_irq() ? -1 : current -> pid,	\
              __FUNCTION__, __LINE__ , ##args )

#define HPRINT( format, args... ) HFORMAT( printk, format, ##args )
#define HPANIC( format, args... ) HFORMAT( panic, format, ##args )

#if defined( DOOR_DEBUG )
/* gcc extension */
#define HASSERT( E )                ({ if( ! ( E ) ) HPANIC( #E ); })
#define HDEBUG( format, args... )   HPRINT( format, ##args )
#else
#define HASSERT( E )
#define HDEBUG( format, args... )
#endif

#define TRACE  HDEBUG( "pid: %i", ( current != NULL ) ? current -> pid : 0 )

#define min( x, y ) ( ( ( x ) < ( y ) ) ? ( x ) : ( y ) )

#define DOOR_DEFAULT_MODE 0600

typedef enum { door_scalar_arg, 
	       door_buffer_arg, 
	       door_pages_arg,
	       door_fd_arg } door_arg_type;

typedef union door_arg_data 
{
	long scalar;
	struct
	{
		void *buffer;
		size_t length;
	} buffer;
	struct
	{
		void *start_address;
		int pages;
	} pages;
	int fd;
} door_arg_data;

typedef struct door_arg_header
{
	int            flags;
	door_arg_type  type;
} door_arg_header;

typedef struct door_bstack
{
	int   free;
	void *sp;
} door_bstack;

typedef enum { door_entry_kernel, door_entry_user } door_entry_type;
typedef struct door_entry
{
	door_entry_type type;
	union {
		struct {
			void  *pc;
			int    stacks_num;
			void **sp;
		} user;
	} u;
} door_entry;

typedef struct door_setup
{
	door_entry       entry;
	int              signum;
	int              arg_num;
	door_arg_header *args;
} door_setup;

typedef enum { door_context_kernel, door_context_user } door_context_type;
typedef struct door_context
{
	door_context_type type;
	union {
		struct pt_regs  user;
	} u;
} door_context;

static const unsigned int max_ref_count = 0xffffffff - 100;

typedef struct door 
{
	atomic_t              initialised;
	unsigned int          ref_count;
	struct task_struct   *server;
	door_context          entry;
	struct dentry        *dentry;
	struct list_head      activations;
	struct list_head      all_doors;
	int                   arg_num;
	door_arg_header      *args;
	int                   bstacks_num;
	int                   bstacks_free;
	door_bstack          *bstacks;
	struct semaphore      boot_sem;
	int                   signum;

	spinlock_t lock;
} door;

/* sub-struct of task_struct, saved/restored on door crossing */
typedef struct door_saved_state
{
	unsigned long flags;	/* should be copied selectively XXX */
	int sigpending;
	mm_segment_t addr_limit;
	struct exec_domain *exec_domain;
	unsigned long policy;
	struct mm_struct *mm;
	struct mm_struct *active_mm;
	struct linux_binfmt *binfmt;
	int exit_code, exit_signal;
	int pdeath_signal;
	unsigned long personality;
	/* process credentials: this is saved/restored if door is suid. */
	uid_t uid,euid,suid,fsuid;
	gid_t gid,egid,sgid,fsgid;
	kernel_cap_t   cap_effective, cap_inheritable, cap_permitted;
	int keep_capabilities:1;
	struct user_struct *user;
	struct thread_struct thread;
	struct signal_struct *sig;
	sigset_t blocked;
	struct sigpending pending;
	unsigned long sas_ss_sp;
	size_t sas_ss_size;
	int (*notifier)(void *priv);
	void *notifier_data;
	sigset_t *notifier_mask;
} door_saved_state;

typedef struct door_trespasser
{
	struct task_struct     *client;
	unsigned int 		flags;
	door_saved_state        state;
	door_context            entry;
	door_context            exit;
	door                   *gate;
	door_arg_data          *copyin;
	int                     bstack;
	struct list_head        chain;
} door_trespasser;

static LIST_HEAD( doors );
static spinlock_t doors_spinlock;

struct door_inode_info {
	struct door		*di_door;
};
static struct vfsmount *door_mnt;
static struct inode_operations door_inode_ops = {
};

static int door_open( struct inode *inode, struct file *file );
extern struct file *alloc_empty_file(int, const struct cred *);

static struct file_operations door_fops = {
	open:		door_open,
//	release:	door_release,
};

static void door_lock_init(void)
{
    spin_lock_init(&doors_spinlock);
}
static void door_lock( door *door )
{
	HASSERT( door != NULL );
	spin_lock( &door -> lock );
}

static void door_unlock( door *door )
{
	HASSERT( door != NULL );
	spin_unlock( &door -> lock );
}

static void doors_lock( void )
{
	spin_lock( &doors_spinlock );
}

static void doors_unlock( void )
{
	spin_unlock( &doors_spinlock );
}

static void dump_ucontext( struct pt_regs *context )
{
	HASSERT( context != NULL );

	printk( "context: bx: %lx, cx: %lx, dx: %lx, si: %lx, di: %lx, bp: %lx, ax: %lx,orig_rax: %lx, rip: %lx, cs: %x, eflags: %lx, rsp: %lx, ss: %x\n", 
		context -> bx,
		context -> cx,
		context -> dx,
		context -> si,
		context -> di,
		context -> bp,
		context -> ax,
		context -> orig_ax,
		context -> ip,
		context -> cs,
		context -> flags,
		context -> sp,
		context -> ss );
}


static void dump_door( door *gate )
{
	printk( "door: %p\n", gate );
	if( gate != NULL ) {
		printk( "\tinit: %i server: %i", 
			atomic_read( &gate -> initialised ), 
			( gate -> server ) ? gate -> server -> pid : 0 );
		printk( "\tuser entry point: " );
		dump_ucontext( &gate -> entry.u.user );
		printk( "\tdentry: %*.*s\n", DNAME_INLINE_LEN, DNAME_INLINE_LEN,
			gate -> dentry -> d_iname );
		printk( "\targs: %i\n", gate -> arg_num );
	}
}


static void dump_doors( const char *header )
{
	struct list_head *scan;

	doors_lock();
	printk( "Doors: %s\n", header );
	list_for_each( scan, &doors ) {
		dump_door( list_entry( scan, door, all_doors ) );
	}
	printk( "Done doors.\n" );
	doors_unlock();
}

static door *door_find( struct dentry *dentry )
{
	struct list_head *scan;
	door *result;

	HASSERT( dentry != NULL );

	result = NULL;
	list_for_each( scan, &doors ) {
		door *gate;

		gate = list_entry( scan, door, all_doors );
		if( gate -> dentry == dentry ) {
			result = gate;
			break;
		}
	}
	return result;
}


static door *door_alloc( int flags )
{
	door *door;

	door = kmalloc( sizeof *door, flags );
	if( door != NULL ) {
		spin_lock_init( &door -> lock );
		atomic_set( &door -> initialised, 0 );
		door -> server = NULL;
		door -> dentry = NULL;
		INIT_LIST_HEAD( &door -> activations );
		INIT_LIST_HEAD( &door -> all_doors );
		memset( &door -> entry, 0, sizeof door -> entry );
		door -> arg_num = 0;
		door -> args = NULL;
		door -> bstacks_num = 0;
		door -> bstacks_free = 0;
		door -> bstacks = NULL;
	}
	return door;
}


static void door_free( door *door )
{
	HASSERT( door != NULL );
	HASSERT( list_empty( &door -> activations ) );
	HASSERT( list_empty( &door -> all_doors ) );
	HASSERT( !spin_is_locked( &door -> lock ) );

	if( door -> args != NULL ) {
		kfree( door -> args );
	}
	if( door -> bstacks != NULL ) {
		kfree( door -> bstacks );
	}
	return kfree( door );
}


static void get_door( door *door )
{
	HASSERT( door != NULL );

	door_lock( door );
	if( door -> ref_count < max_ref_count ) {
		++ door -> ref_count;
	}
	door_unlock( door );
}

static int put_door( door *door ) 
{
	int recycle;

	HASSERT( door != NULL );
	HASSERT( door -> ref_count > 0 );

	door_lock( door );
	if( door -> ref_count < max_ref_count ) {
		-- door -> ref_count;
	}
	recycle = ( door -> ref_count == 0 );
	door_unlock( door );
	if( recycle ) {
		door_free( door );
	}
	return !recycle;
}


static int door_open( struct inode *inode, struct file *file )
{
	door *door;
	int result;

	HASSERT( inode != NULL );
	HASSERT( file != NULL );


	doors_lock();
	door = door_find( file->f_path.dentry );
	if( door == NULL ) {
		door = door_alloc( GFP_KERNEL );
		if( door != NULL ) {
			list_add( &door -> all_doors, &doors );
			door -> dentry = file->f_path.dentry;
		}
	}
	if( door != NULL ) {
		door_lock( door );
		file -> private_data = door;
		door_unlock( door );
		get_door( door );
		result = 0;
	} else {
		result = -ENOMEM;
	}
	doors_unlock();

	return result;
}


static int door_get_bstack( door *door, unsigned int flags )
{
	int i;

	HASSERT( door != NULL );

	if( ( flags & O_NONBLOCK ) && ( door -> bstacks_free == 0 ) )
		return -EAGAIN;

	while( door -> bstacks_free <= 0 ) {
		door_unlock( door );
		down_interruptible( &door -> boot_sem );
		door_lock( door );
	}

	for( i = 0 ; i < door -> bstacks_num ; ++i ) {
		if( door -> bstacks[ i ].free ) {
			door -> bstacks[ i ].free = 0;
			-- door -> bstacks_free;
			HASSERT( door -> bstacks_free >= 0 );
			return i;
		}
	}
	return -EAGAIN;
}

static void door_put_bstack( door *door, int bstack )
{
	HASSERT( door != NULL );
	HASSERT( ( 0 <= bstack ) && ( bstack < door -> bstacks_num ) );
	
	door -> bstacks[ bstack ].free = 1;
	++ door -> bstacks_free;
	HASSERT( door -> bstacks_free <= door -> bstacks_num );
	up( &door -> boot_sem );
}


static struct pt_regs *uregs( void )
{
	return ( struct pt_regs * )
		( ( ( char * ) current ) + 2 * PAGE_SIZE - 
		  sizeof( struct pt_regs ) );
}


static void door_save_ucontext( door_context *context )
{
	HASSERT( context != NULL );
	context -> u.user = *uregs();
}

static void door_restore_ucontext( door_context *context )
{
	HASSERT( context != NULL );
	*uregs() = context -> u.user;
}

static int door_init_bstacks( door *gate, door_entry *entry )
{
	int result;
	int bstacks;

	HASSERT( gate != NULL );
	HASSERT( entry != NULL );
  
	bstacks = entry -> u.user.stacks_num;
	result = 0;
	if( bstacks > 0 ) {
		gate -> bstacks_num = bstacks;
		gate -> bstacks = kmalloc( bstacks * sizeof( door_bstack ),
					   GFP_KERNEL );
		if( gate -> bstacks != NULL ) {
			int i;
			for( i = 0 ; ( i < bstacks ) &&
				     get_user( gate -> bstacks[ i ].sp, 
					       &entry -> u.user.sp[ i ] ) == 0 ; 
			     gate -> bstacks[ i++ ].free = 1 )
				{;}
			if( i == bstacks ) {
				sema_init( &gate -> boot_sem, 
					   gate -> bstacks_num );
				gate -> bstacks_free = bstacks;
			} else
				result = -EFAULT;
		} else
			result = -ENOMEM;
	} else
		result = -EINVAL;
	if( ( result != 0 ) && ( gate -> bstacks != NULL ) ) {
		gate -> bstacks_num = 0;
		kfree( gate -> bstacks );
		gate -> bstacks = NULL;
		gate -> bstacks_free = 0;
	}
	return result;
}

static int door_init( door *door, door_setup *setup )
{
	int result;

	HASSERT( door != NULL );
	HASSERT( setup != NULL );
  
	result = 0;
	if( setup -> arg_num < 0 ) {
		result = -EINVAL;
	} else if( setup -> entry.type == door_entry_user ) {
		int bytes;
		
		door -> server = current;
		door_save_ucontext( &door -> entry );
		door -> entry.u.user.ip = ( long ) setup -> entry.u.user.pc;
		door -> signum = setup -> signum;
		door -> arg_num = setup -> arg_num;
		bytes = sizeof( door_arg_header ) * door -> arg_num;
		door -> args = kmalloc( bytes, GFP_KERNEL );
		if( door -> args != NULL )
			result = door_init_bstacks( door, &setup -> entry );
		else 
			result = -ENOMEM;
	} else {
		HPRINT( "Kernel entry points are not supported yet." );
		result = -ENOSYS;
	}
	if( ( result != 0 ) && ( door -> args != NULL ) ) {
		door -> arg_num = 0;
		kfree( door -> args );
		door -> args = NULL;
	}
	return result;
}

/*
static int _alloc_door_fd(int __user *filde)
{
	struct file *file;
	int fd;
	int error;

	error = __do_pipe_flags(fd, file, 0);
	if (!error) {
		if (unlikely(copy_to_user(filde, fd, sizeof(fd)))) {
			fput(file);
			put_unused_fd(fd);
			error = -EFAULT;
		} else {
			fd_install(fd, file);
		}
	}
	return error;
}
*/

static struct inode *door_inode_alloc(struct door *dr)
{
	struct inode *ino;
	//struct door_inode_info *info;

	ino = new_inode(door_mnt->mnt_sb);
	if (!ino)
		return 0;

	ino->i_mode = S_IFIFO | DOOR_DEFAULT_MODE;
	ino->i_uid = current_fsuid();
	ino->i_gid = current_fsgid();

	ino->i_atime = ino->i_mtime = ino->i_ctime = current_time(ino);
	ino->i_op = &door_inode_ops;
	ino->i_fop = &door_fops;
	ino->i_blkbits = blksize_bits(PAGE_SIZE);

	/*
	 * A useful suggestion from linux/fs/pipe.c:
	 *
	 * Mark the inode dirty from the very beginning,
	 * that way it will never be moved to the dirty
	 * list because "mark_inode_dirty()" will think
	 * that it already _is_ on the dirty list.
	 */
	ino->i_state = I_DIRTY;

	//info = get_door_inode_info(ino);
	//info->di_door = dr;

	return ino;
}

static struct dentry *door_dentry_alloc(struct inode *ino)
{
	struct dentry *dent;
	struct qstr this;
	char name[32];

	sprintf(name, "[%lu]", ino->i_ino);
	this.name = name;
	this.len = strlen(name);
	this.hash = ino->i_ino; /* will go */
	dent = d_alloc(door_mnt->mnt_sb->s_root, &this);
	if (!dent)
		goto bad_d_alloc;
	d_add(dent, ino);

bad_d_alloc:
	return dent;
}

static int door_create_fd(struct door *dr)
{
	int fd;
	struct file *filp;
	struct inode *ino;
    struct path path;
	int error;

	fd = get_unused_fd_flags(0);

	if (fd < 0)
		return fd;

	error = -ENFILE;
	filp = alloc_empty_file(0, current_cred());
	if (IS_ERR(filp))
		goto bad_filp;

	filp->f_op = &door_fops;
	filp->f_mode = 3;
	filp->f_flags = O_RDWR;
	filp->f_pos = 0;

	error = -ENOMEM;
	ino = door_inode_alloc(dr);
	if (!ino)
		goto bad_inode_alloc;

	error = -ENOMEM;
	filp->f_path.dentry = door_dentry_alloc(ino);
	if (!filp->f_path.dentry->d_inode)
		goto bad_dent;

	filp->f_path.mnt = mntget(door_mnt);

	//current->files->fd[fd] = filp;
	dr->ref_count++;

	//DOOR_DENTRY_COUNTS("door_create_fd", filp->f_path.dentry->d_inode);


    fd_install(fd, filp);
	return fd;

bad_dent:
bad_inode_alloc:
	fput(filp);
bad_filp:
	put_unused_fd(fd);
	return error;
}


static void door_init_trespasser( door_trespasser *trespasser, 
				  struct task_struct *client, struct file *file )
{
	HASSERT( trespasser != NULL );
	HASSERT( client != NULL );
	HASSERT( file != NULL );

	trespasser -> client = client;
	trespasser -> flags = file -> f_flags;
}


static int door_enter( door *door, door_trespasser *trespasser )
{
	int result;

	HASSERT( door != NULL );
	HASSERT( door -> server != NULL );
	HASSERT( trespasser != NULL );
	HASSERT( trespasser -> client != NULL );

# define SAVF( field )						\
  trespasser -> state.field = trespasser -> client -> field;	\
  trespasser -> client -> field = door -> server -> field

	result = 0;
	list_add( &trespasser -> chain, &door -> activations );
	trespasser -> gate = door;
	/* update trespasser -> client struct. */
	/* SAVF( flags );	should be copied selectively XXX */
	SAVF( pending );
	//SAVF( addr_limit );
	//get_exec_domain( door -> server -> exec_domain );
	//SAVF( exec_domain );
	/* SAVF( policy ); */
	atomic_inc( &door -> server -> mm -> mm_users );
	SAVF( mm );
	SAVF( active_mm );
//	SAVF( binfmt );
	/* SAVF( exit_code ); */
	/* SAVF( exit_signal ); */
	/* SAVF( pdeath_signal ); */
	SAVF( personality );
	/* process credentials: this is saved/restored if door is suid. 
	   uid_t uid,euid,suid,fsuid;
	   gid_t gid,egid,sgid,fsgid;
	   kernel_cap_t   cap_effective, cap_inheritable, cap_permitted;
	   int keep_capabilities:1;
	   struct user_struct *user; */
	SAVF( blocked );
	SAVF( pending );
	SAVF( sas_ss_sp );
	SAVF( sas_ss_size );


	door_save_ucontext( &trespasser -> exit );
	door_restore_ucontext( &trespasser -> entry );
//	door_flush_ucontext( &trespasser -> entry );
	activate_mm( trespasser -> state.mm, trespasser -> client -> mm );

	if( result != 0 )
		list_del( &trespasser -> chain );
	return result;
}



static int __door_call( door *gate, struct file *fp, door_arg_data *uargs )
{
	int result;

	HASSERT( gate != NULL );
	HASSERT( fp != NULL );
	HASSERT( uargs != NULL );

	result = 0;
	if( atomic_read( &gate -> initialised ) > 0 ) {
		int bstack;
		int bytes;
		door_trespasser *tres;
			
		bstack = door_get_bstack( gate, fp -> f_flags );
		if( bstack < 0 ) {
			return -EAGAIN;
		}

		bytes = gate -> arg_num * sizeof( door_arg_data );
		tres = kmalloc( ( sizeof *tres ) + bytes, GFP_KERNEL );
		if( tres != NULL ) {
			tres -> copyin = ( void * ) ( tres + 1 );
			memset( tres -> copyin, 0, bytes );
			door_init_trespasser( tres, current, fp );
			if( !copy_from_user( tres -> copyin, uargs, bytes ) ) {
				tres -> bstack = bstack;
				tres -> entry = gate -> entry;
				tres -> entry.u.user.sp = 
					( long ) gate -> bstacks[ bstack ].sp;
				result = door_enter( gate, tres );
			} else
				result = -EFAULT;
		} else
			result = -ENOMEM;
		if( ( result != 0 ) && ( tres != NULL ) )
			kfree( tres );
	} else
		result = -ENOENT;
	return result;
}

static int door_msg( struct file *file, 
		       unsigned int cmd, unsigned long arg )
{
	int result;
	door *gate;

	HASSERT( file != NULL );

	gate = ( door * ) file -> private_data;
	HASSERT( gate != NULL );

	result = 0;
	get_door( gate );
	door_lock( gate );
	switch( cmd ) {
	case DOOR_OPEN: {
		door_setup setup;

		if( !copy_from_user( &setup, ( void * ) arg, sizeof setup ) ) {
			if( atomic_read( &gate -> initialised ) == 0 ) {
				setup.entry.type = door_entry_user;
				result = door_init( gate, &setup );
				if( result == 0 )
					atomic_set( &gate -> initialised, 1 );
			} else
				result = -EBUSY;
		} else
			result = -EFAULT;
		break;
	}
	case DOOR_CALL:
		result = __door_call( gate, file, ( door_arg_data * ) arg );
		break;

	default:
		result = -ENOTTY;
	}
	door_unlock( gate );
	put_door( gate );

	return result;
}



int door_internal_functions(int door_ops, int fd , unsigned long arg)
{



}


