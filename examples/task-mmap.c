#include <stdio.h>
#include "dtt.h"

void task_write_memory(dt_buf_t *args, dt_buf_t *ret)
{
    // Map memory
    char *ptr = (char *)dt_mmap((dt_addr_t *)args->data);

    char *str = "Hello world!";
    sprintf(ptr, str);
    printf("Say: %s\n", str);

    // Unmap memory
    dt_munmap((dt_addr_t *)args->data);
}

DT_DECLARE_TASK(task_write_memory);

int main()
{
    char buf[32] = { 0 };

    // Initialize distributed task system, must be called at the very beginning of `main()`
    dt_init();

    // Allocate memory remotely
    dt_addr_t *addr = dt_malloc(0, 128);

    // Create task
    dt_buf_t *args = (dt_buf_t *)malloc(sizeof(dt_buf_t));
    args->len = sizeof(dt_addr_t);
    args->data = (char *)addr;
    int task_id = dt_task_create(DT_ADDR2SSID(addr), task_write_memory, args, NULL);

    // Wait for task completion
    dt_join(task_id);

    dt_memcpy_from(buf, addr, sizeof(buf));
    printf("Task say: %s\n", buf);

    // Free memory
    dt_free(addr);

    return 0;
}
