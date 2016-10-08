#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/init.h"

static void syscall_handler (struct intr_frame *);

typedef int pid_t;

static void sys_halt(void);
static void sys_exit(int status);
static pid_t sys_exec(const char* cmd_line);
static int sys_wait(pid_t pid);
static bool sys_create(const char* file, unsigned initial_size);
static bool sys_remove(const char* file);
static int sys_open(const char* file);
static int sys_filesize(int fd);
static int sys_read(int fd, void* buffer, unsigned size);
static int sys_write(int fd, const void* buffer, unsigned size);
static void sys_seek(int fd, unsigned position);
static unsigned sys_tell(int fd);
static void sys_close(int fd);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int args[3];

  if (!is_user_vaddr(f->esp))
  {
    printf("<NOT USER VADDR\n>");
	  sys_exit(-1);
  }


  switch (* (int *) f->esp)
  {
    case SYS_HALT:
    {
      sys_halt();
      break;
    }
    case SYS_EXIT:
    {
      get_args(f, &args, 1);
      sys_exit(args[0]);
      break;
    }
    case SYS_EXEC:
    {
      get_args(f, &args, 1);
      sys_exec(args[0]);
      break;
    }
    case SYS_WAIT:
    {
      get_args(f, &args, 1);
      sys_wait(args[0]);
      break;
    }
    case SYS_CREATE:
      //sys_create();
      break;
    case SYS_REMOVE:
      //sys_remove();
      break;
    case SYS_OPEN:
      //sys_open();
      break;
    case SYS_FILESIZE:
      //sys_filesize();
      break;
    case SYS_READ:
      //sys_read();
      break;
    case SYS_WRITE:
      //sys_write();
      get_args(f, &args, 3);
      printf("%s", args[1]);
      break;
    case SYS_SEEK:
      //sys_seek();
      break;
    case SYS_TELL:
      //sys_tell();
      break;
    case SYS_CLOSE:
      //sys_close();
      break;
  }  
}

static void sys_halt()
{
  shutdown_power_off();
}

static void sys_exit(int status)
{
  thread_current()->exit_status = status;
  thread_exit();
}

static pid_t sys_exec(const char* cmd_line) 
{
  //Implementation incomplete
  pid_t pid = process_execute(cmd_line);

  return pid;
}

static int sys_wait(pid_t pid) 
{
  return process_wait(pid); //Need to implement this function in process.c
}

static bool sys_create(const char* file, unsigned initial_size) {}
static bool sys_remove(const char* file) {}
static int sys_open(const char* file) {}
static int sys_filesize(int fd) {}
static int sys_read(int fd, void* buffer, unsigned size) {}
static int sys_write(int fd, const void* buffer, unsigned size) {}
static void sys_seek(int fd, unsigned position) {}
static unsigned sys_tell(int fd) {}
static void sys_close(int fd) {}

void get_args(struct intr_frame *f, int* args, int n)
{
  // Stack pointer is pointing at the syscall number (int), args start just past that
  int * stack_args = f->esp + sizeof(int);

  for (int i = 0; i < n; i++)
    {
      if (!is_user_vaddr((const void *)stack_args))
	      sys_exit(-1);

      // Copy arg from stack to caller's buffer
      args[i] = stack_args[i];
    }
}
