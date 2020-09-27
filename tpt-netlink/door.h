#ifndef __DOOR_H__
#define __DOOR_H__


#define DOOR_ARG_IN    0x0001
#define DOOR_ARG_OUT   0x0002
#define DOOR_ARG_INOUT ( DOOR_ARG_IN | DOOR_ARG_OUT )

// open door and initialize it if nt before
#define DOOR_OPEN  0xd001d001
// close the door
#define DOOR_CLOSE  0xd001d002
// door call invocation and switch to another domain
#define DOOR_CALL 0xd001d003

int door_internal_functions(int door_ops, int fd , unsigned long arg);


#endif //__DOOR_H__