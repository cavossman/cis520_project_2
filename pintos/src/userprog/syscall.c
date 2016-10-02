#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threas/vaddr.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  if (!is_user_vaddr(f))
  {
	  //sys_exit(-1);
	  return;
  }
	
  switch (* (int *) f->esp)
  {
    case SYS_HALT:
      sys_halt();
      break;
    case SYS_EXIT:
      sys_exit();
      break;
    case SYS_EXEC:
      sys_exec();
      break;
    case SYS_WAIT:
      sys_wait();
      break;
    case SYS_CREATE:
      sys_create();
      break;
    case SYS_REMOVE:
      sys_remove();
      break;
    case SYS_OPEN:
      sys_open();
      break;
    case SYS_FILESIZE:
      sys_filesize();
      break;
    case SYS_READ:
      sys_read();
      break;
    case SYS_WRITE:
      sys_write();
      break;
    case SYS_SEEK:
      sys_seek();
      break;
    case SYS_TELL:
      sys_tell();
      break;
    case SYS_CLOSE:
      sys_close();
      break;
  }  
}

bool sys_halt() {}
bool sys_exit() {}
bool sys_exec() {}
bool sys_wait() {}
bool sys_create() {}
bool sys_remove() {}
bool sys_open() {}
bool sys_filesize() {}
bool sys_read() {}
bool sys_write() {}
bool sys_seek() {}
bool sys_tell() {}
bool sys_close() {}


