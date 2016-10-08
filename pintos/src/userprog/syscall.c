#include <stdio.h>
#include <syscall-nr.h>
#include "process.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/off_t.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"

#define EXECUTABLE_START (void *)0x08048000

struct lock file_sys_lock;
struct process_file
{
  struct file* file;
  struct lock file_lock;
  int file_descriptor;
  struct list_elem elem;
};

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

bool valid_ptr(const void* ptr);
int create_kernel_ptr(const void* ptr);

static void get_args(struct intr_frame *f, int* args, int n);

void
syscall_init (void) 
{
  lock_init(&file_sys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int args[3];

  void * esp = create_kernel_ptr(f->esp);  

  switch (*(int *)esp)
  {
    case SYS_HALT:
    {
      sys_halt();
      break;
    }
    case SYS_EXIT:
    {
      get_args(f, args, 1);
      sys_exit(args[0]);
      break;
    }
    case SYS_EXEC:
    {
      get_args(f, args, 1);
      args[0] = create_kernel_ptr((const void *)args[0]);
      f->eax = sys_exec((const char *)args[0]);
      break;
    }
    case SYS_WAIT:
    {
      get_args(f, args, 1);
      f->eax = sys_wait(args[0]);
      break;
    }
    case SYS_CREATE:
    {
      get_args(f, args, 2);
      args[0] = create_kernel_ptr((const void *)args[0]);
      f->eax = sys_create((const char *)args[0], (unsigned) args[1]);
      break;
    }
    case SYS_REMOVE:
      get_args(f, args, 1);
      args[0] = create_kernel_ptr((const void *)args[0]);
      f->eax = sys_remove((const char *) args[0]);
      break;
    case SYS_OPEN:
      get_args(f, &args[0], 1);
      args[0] = create_kernel_ptr((const void *)args[0]);
      f->eax = sys_open((const char *)args[0]);
      break;
    case SYS_FILESIZE:
      get_args(f, args, 1);
      f->eax = sys_filesize(args[0]);
      break;
    case SYS_READ:
      //sys_read();
      break;
    case SYS_WRITE:
      get_args(f, args, 3);
      //sys_write();
      printf("%s", (char *)args[1]);
      break;
    case SYS_SEEK:
      get_args(f, args, 2);
      sys_seek(args[0], args[1]);    
      break;
    case SYS_TELL:
      get_args(f, args, 1);
      f->eax = sys_tell(args[0]);
      break;
    case SYS_CLOSE:
    {
      get_args(f, args, 1);
      sys_close(args[0]);
      break;
    }
  }
}

static struct process_file* get_process_file(int file_descriptor)
{
  /* Acquire file system lock                               */
  lock_acquire(&file_sys_lock);

  /* Get current thread                                     */
  struct thread* cur = thread_current();
  struct list_elem* cur_elem;

  /* Iterate over file list of the current thread           */
  for(cur_elem = list_begin(&cur->file_list);
      cur_elem != list_end(&cur->file_list);
      cur_elem = list_next(cur_elem))
  {
    /* Get the process file which holds the current element */
    struct process_file *pf = list_entry(cur_elem, struct process_file, elem);
    if(pf != NULL && file_descriptor == pf->file_descriptor)
      {
        /* Return the file pointer if descriptors match     */
        lock_release(&file_sys_lock);
        return pf;  
      }
  }
  /* Return NULL if the file does not exist                 */  
  lock_release(&file_sys_lock);
  return NULL;
}


static void sys_halt()
{
  shutdown_power_off();
}

static void sys_exit(int status)
{
  struct thread * cur = thread_current();
  cur->exit_status = status;
  printf("%s: exit(%d)\n", cur->name, cur->exit_status);
  thread_exit();
}

static pid_t sys_exec(const char* cmd_line) 
{
  //Implementation incomplete
  pid_t pid = process_execute(cmd_line);

  // Return PID appropriately
  return thread_wait_for_load(pid) ? pid : -1;
}

static int sys_wait(pid_t pid) 
{
  return process_wait(pid);
}

static bool sys_create(const char* file, unsigned initial_size) 
{
  lock_acquire(&file_sys_lock);
  bool success = filesys_create(file, initial_size);
  lock_release(&file_sys_lock);
  return success;
}

static bool sys_remove(const char* file) 
{
  lock_acquire(&file_sys_lock);
  bool success = filesys_remove(file);
  lock_release(&file_sys_lock);
  return success;
}

static int sys_open(const char* file) 
{
  lock_acquire(&file_sys_lock);

  struct file* f;
  struct thread* cur = thread_current();
  struct process_file* pf;

  f = filesys_open(file);
  if(f == NULL)
  {
    lock_release(&file_sys_lock);
    return -1;
  }

  pf = malloc(sizeof(struct process_file));
  pf->file = f;
  pf->file_descriptor = cur->fd++;
  list_push_back(&cur->file_list, &pf->elem);

  lock_release(&file_sys_lock);
  return pf->file_descriptor;
}


static int sys_filesize(int fd)
{
  int file_size;

  struct process_file* pf = get_process_file(fd);
  lock_acquire(&(pf->file_lock));
  if(pf->file == NULL)
  {
    lock_release(&(pf->file_lock));
    return -1;
  }

  file_size = file_length(pf->file);
  lock_release(&(pf->file_lock));
  return file_size;
}


static int sys_read(int fd, void* buffer, unsigned size) {}
static int sys_write(int fd, const void* buffer, unsigned size) {}


static void sys_seek(int fd, unsigned position)
{
  struct process_file* pf = get_process_file(fd);
  lock_acquire(&(pf->file_lock));
  if(pf->file == NULL)
  {
    lock_release(&(pf->file_lock));
    return;
  }

  file_seek(pf->file, position);
  lock_release(&(pf->file_lock));
}


static unsigned sys_tell(int fd)
{
  off_t pos;

  struct process_file* pf = get_process_file(fd);
  lock_acquire(&(pf->file_lock));

  if(pf->file == NULL)
  {
    lock_release(&(pf->file_lock));
    return -1;
  }

  pos = file_tell(pf->file);
  lock_release(&(pf->file_lock));
  return pos;
}


static void sys_close(int fd) 
{
  if (file_sys_lock.holder != NULL || fd <= STDOUT_FILENO || fd >= 0x20101234)
    sys_exit(-1);

  lock_acquire(&file_sys_lock);

  struct thread *cur = thread_current();
  struct list_elem *next, *e = list_begin(&cur->file_list);

  while (e != list_end (&cur->file_list))
  {
    next = list_next(e);
    struct process_file *pf = list_entry (e, struct process_file, elem);
    if (fd == pf->file_descriptor || fd == -1)
      {
        file_close(pf->file);
        list_remove(&pf->elem);
        free(pf);
        if (fd != -1)
        {
          return;
        }
      }
      e = next;
  }

  lock_release(&file_sys_lock);
}

static void get_args(struct intr_frame *f, int* args, int n)
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

bool valid_ptr(const void* ptr)
{
  return(!(!is_user_vaddr(ptr) || ptr < EXECUTABLE_START ));
}


int create_kernel_ptr(const void* ptr)
{
  // TO DO: Need to check if all bytes within range are correct
  // for strings + buffers
  if (!valid_ptr(ptr))
    sys_exit(-1);
  void *temp = pagedir_get_page(thread_current()->pagedir, ptr);
  if (!temp)
    {
      sys_exit(-1);
    }
  return (int) temp;
}
