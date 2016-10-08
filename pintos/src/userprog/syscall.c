#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/init.h"

struct lock file_lock;
struct process_file
{
  struct file* file;
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
	  sys_exit(-1);
	


  switch (* (int *) f->esp)
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
      f->eax = sys_exec(args[0]);
      break;
    }
    case SYS_WAIT:
    {
      get_args(f, args, 1);
      f->eax = sys_wait(args[0]);
      break;
    }
    case SYS_CREATE:
      get_args(f, args, 2);
      f->eax = sys_create(args[0], args[1]);
      break;
    case SYS_REMOVE:
      get_args(f, args, 1);
      f->eax = sys_remove(args[0]);
      break;
    case SYS_OPEN:
      get_args(f, args, 1);
      f->eax = sys_open(args[0]);
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

static file* get_file(int file_descriptor)
{
  /* Get current thread                                     */
  struct thread* cur = thread_current();
  struct list_elem* cur_elem;

  /* Iterate over file list of the current thread           */
  for(e = list_begin(&cur->file_list);
      cur_elem != list_end(&cur->file_list);
      e = list_next(cur_elem))
  {
    /* Get the process file which holds the current element */
    struct process_file *pf = list_entry(cur_elem, struct process_file, elem);
    if(pf != NULL && file_descriptor == pf->file_descriptor)
      {
        /* Return the file pointer if descriptors match     */
        return pf->file;  
      }
  }
  /* Return NULL if the file does not exist                 */  
  return NULL;
}


static void sys_halt()
{
  shutdown_power_off();
}

static void sys_exit(int status)
{
  struct thread* cur = thread_current();
  if (thread_is_alive(cur->parent))
    cur->child_process->status = status;
  thread_exit();
}

static pid_t sys_exec(const char* cmd_line) 
{
  pid_t pid = process_execute(cmd_line);

  struct thread* cur = thread_current();

  struct child_process* cp;
  bool cp_found = false;

  struct list_elem* e = list_begin(&cur->children);
  
  while (e != list_end(&cur->children) && !cp_found)
  {
    cp = list_entry(e, struct child_process, elem);
    if (pid == cp->pid)
      cp_found = true;
    else
      e = list_next(e);
  }

  ASSERT(cp_found);

  while(cp->load == NOT_LOADED)
    barrier();

  if (cp->load == LOAD_FAILURE)
    return -1;

  return pid;
}

static int sys_wait(pid_t pid) 
{
  return process_wait(pid);
}

static bool sys_create(const char* file, unsigned initial_size) 
{
  lock_acquire(&file_lock);
  bool success = filesys_create(file, initial_size);
  lock_release(&file_lock);
  return success;
}
static bool sys_remove(const char* file) 
{
  lock_acquire(&file_lock);
  bool success = filesys_remove(file);
  lock_release(&file_lock);
  return success;
}
static int sys_open(const char* file) 
{
  lock_acquire(&file_lock);
  struct file* f = filesys_open(file);

  if(f == NULL)
  {
    lock_release(&file_lock);
    return -1;
  }

  struct thread* cur = thread_current();
  struct process_file* pf = malloc(sizeof(struct process_file));
  pf->file = f;
  pf->file_descriptor = cur->fd++;
  list_push_back(&cur->file_list, &pf->elem);

  lock_release(&file_lock);
  return pf->file_descriptor;
}


static int sys_filesize(int fd) {
  int file_size;

  lock_acquire(&file_lock);       /* Acquire file lock                */
  struct file* f = get_file(fd);  /* Get file to be sized             */
  if(f == NULL)
  {
    lock_release(&file_lock);     /* If file does not exist, release  */
    return -1;                       /* lock and return error         */
  }

  file_size = file_length(f);     /* Get file size                    */
  lock_release(&file_lock);       /* Release lock                     */
  return file_size;               /* Return file size                 */
}


static int sys_read(int fd, void* buffer, unsigned size) {}
static int sys_write(int fd, const void* buffer, unsigned size) {}
static void sys_seek(int fd, unsigned position) {}
static unsigned sys_tell(int fd) {}
static void sys_close(int fd) {}

void get_args(struct intr_frame *f, int* args, int numArgs)
{
  int* ptr;
  for (int i = 0; i < numArgs; i++)
  {
    ptr = (int*)f->esp + i + 1;
    if (!is_user_vaddr(ptr))
	    sys_exit(-1);
    args[i] = *ptr;
  }
}
