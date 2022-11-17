#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/slab.h>

// Meta Information
MODULE_LICENSE("GPL");
MODULE_AUTHOR("ME");
MODULE_DESCRIPTION("A module that knows how to greet");

int pid;

/*
 * module_param(foo, int, 0000)
 * The first param is the parameters name
 * The second param is it's data type
 * The final argument is the permissions bits,
 * for exposing parameters in sysfs (if non-zero) at a later stage.
 */
void simple_traverse(struct task_struct* task) {
    printk("mymodulePID: %d \n",task->pid);
    printk("mymoduleParentPID: %d \n",task->parent->pid);
    printk("mymoduleTime: %lld \n",task->start_time);
    
    long long createTime=-1;
    int oldChildPID=-1;
    struct list_head *list;
    struct task_struct *toturn;
    struct task_struct *toage;
    //GET OLDEST CHILD
    list_for_each(list, &task->children) {
    toage = list_entry(list, struct task_struct, sibling);
    /* task now points to one of current's children */
    if(createTime<0){
    createTime=toage->start_time;
    oldChildPID=toage->pid;
    }
    else if(toage->start_time < createTime)
    {
    createTime=toage->start_time;
    oldChildPID=toage->pid;
    }
    }
    printk("mymoduleOLD: %d \n",oldChildPID);
	
    //ITERATE
    list_for_each(list, &task->children) {
    toturn = list_entry(list, struct task_struct, sibling);
    /* task now points to one of current's children */
    simple_traverse(toturn);
	}
}


module_param(pid, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(pid, "pid given");

// A function that runs when the module is first loaded
int simple_init(void) { //MAIN
  struct task_struct *ts;
  
  ts = get_pid_task(find_get_pid(pid), PIDTYPE_PID);
  //printk("Hello from the kernel, pid: %d\n",  pid);
  //printk("command: %s\n", ts->comm);
  //printk("PID: %d\n", ts->pid);
  //printk("start time: %lld\n",ts->start_time);
  
  simple_traverse(ts);
	
  return 0;
}

// A function that runs when the module is removed
void simple_exit(void) {
  printk("Goodbye from the kernel, pid: %d\n", pid);
}

module_init(simple_init);
module_exit(simple_exit);
