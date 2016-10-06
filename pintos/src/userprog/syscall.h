#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"

struct child_process
{
  int pid;
  int load;
  bool wait;
  bool exit;
  int status;

  struct list_elem elem;

};

void syscall_init (void);

#endif /* userprog/syscall.h */
