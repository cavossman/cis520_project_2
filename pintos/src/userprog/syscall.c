#include "filesys/file.h"
#include "filesys/off_t.h"
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

bool valid_ptr(const void* ptr);
int create_kernel_ptr(const void* ptr);


void
syscall_init (void) 
{
  lock_init(&file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int args[3];

  if (!valid_ptr(f->esp))
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
    {
      get_args(f, args, 2);
      args[0] = create_kernel_ptr(args[0]);
      f->eax = sys_create((const char *)args[0], (unsigned) args[1]);
      break;
    }
    case SYS_REMOVE:
      get_args(f, args, 1);
      args[0] = create_kernel_ptr((const void *) args[0]);
      f->eax = sys_remove((const char *) args[0]);
      break;
    case SYS_OPEN:
      get_args(f, &args[0], 1);
      args[0] = create_kernel_ptr((const void *) args[0]);
      f->eax = sys_open((const char *) args[0]);
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

static struct file* get_file(int file_descriptor)
{
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


static int sys_filesize(int fd)
{
  int file_size;

  lock_acquire(&file_lock);       /* Acquire file lock                */
  struct file* f = get_file(fd);  /* Get file to be sized             */
  if(f == NULL)
  {
    lock_release(&file_lock);     /* If file does not exist, release  */
    return -1;                        /* lock and return error        */
  }

  file_size = file_length(f);     /* Get file size                    */
  lock_release(&file_lock);       /* Release lock                     */
  return file_size;               /* Return file size                 */
}


static int sys_read(int fd, void* buffer, unsigned size) {}
static int sys_write(int fd, const void* buffer, unsigned size) {}
static void sys_seek(int fd, unsigned position) {}

static unsigned sys_tell(int fd)
{
  off_t pos;

  lock_acquire(&file_lock);       /* Acquire file lock                */
  struct file* f = get_file(fd);  /* Get file to be sized             */
  if(f == NULL)
  {
    lock_release(&file_lock);     /* If file does not exist, release  */
    return -1;                        /* lock and return error        */
  }

  pos = file_tell(f);             /* Get position of next byte        */
  lock_release(&file_lock);       /* Release lock                     */
  return pos;                     /* Return position of next byte     */
}


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

bool valid_ptr(const void* ptr)
{
  if (!is_user_vaddr(ptr) || ptr < 0x08048000)
  {
    printf("<NOT USER VADDR\n>");
    return false;
  }

  return true;
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
