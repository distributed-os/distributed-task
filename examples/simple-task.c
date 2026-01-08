#include <stdio.h>
#include "dtt.h"

void task_write_file(dt_buf_t *args, dt_buf_t *ret)
{
    // Create a hello.txt file on the remote node
    system("echo hello >> /tmp/hello.txt");

    printf("task write_file call, args = %p ret = %p ...\n", args, ret);
}

DT_DECLARE_TASK(task_write_file);

int main()
{
    // Distributed task initialization, must be called at the very beginning of `main()`
    dt_init();

    // Create a task
    int task_id = dt_task_create(0, task_write_file, NULL, NULL);
    // Wait for the task to finish
    dt_join(task_id);

    printf("append hello to /tmp/hello.txt\n");

    return 0;
}
