#include <stdio.h>
#include <string.h>

#include "dtt.h"

void task_memory_simple(dt_buf_t *args, dt_buf_t *ret)
{
    // Map memory
    char *ptr = (char *)dt_mmap((dt_addr_t *)args->data);

    char *say = "Hi, i am Bob!";
    printf("Task Receive: %s\n", ptr);

    strcpy(ptr, say);
    printf("Task Say    : %s\n", ptr);

    // Unmap memory
    dt_munmap((dt_addr_t *)args->data);
}

DT_DECLARE_TASK(task_memory_simple);

void run_mem_simple()
{
    char buf[32] = { 0 };

    // Allocate remote memory
    dt_addr_t *addr = dt_malloc(0, 128);
    char *say = "Hi, i am Alice!";
    dt_memcpy_to(addr, say, strlen(say));

    // Create task
    dt_buf_t *args = (dt_buf_t *)malloc(sizeof(dt_buf_t));
    args->len = sizeof(dt_addr_t);
    args->data = (char *)addr;
    int task_id = dt_task_create(DT_ADDR2SSID(addr), task_memory_simple, args, NULL);

    // Wait for task to complete
    dt_join(task_id);

    printf("Say    : %s\n", say);

    dt_memcpy_from(buf, addr, sizeof(buf));
    printf("Receive: %s\n", buf);

    // Free memory
    dt_free(addr);
}

void task_memory_copy(dt_buf_t *args, dt_buf_t *ret)
{
    dt_addr_t *addr1 = (dt_addr_t *)args->data;
    dt_addr_t *addr2 = (dt_addr_t *)(args->data + sizeof(dt_addr_t));

    printf("Memory copy from add1 to addr2\n");

    // (2) Copy the first 32 bytes from addr1 to addr2
    dt_memcpy(addr2, addr1, 32);
}

DT_DECLARE_TASK(task_memory_copy);


void run_mem_copy()
{
    char buf[32] = { 0 };

    // Allocate remote memory
    dt_addr_t *addr1 = dt_malloc(0, 128);
    dt_addr_t *addr2 = dt_malloc(0, 128);
    size_t size = sizeof(dt_addr_t);

    char *say = "Hello, i am from addr1";
    dt_memcpy_to(addr1, say, strlen(say));  // (1) Copy string to addr1

    // Create task
    dt_buf_t *args = (dt_buf_t *)malloc(sizeof(dt_buf_t));
    args->len = 2 * size;
    args->data = malloc(2 * size);
    memcpy(args->data, addr1, size);
    memcpy(args->data + size, addr2, size);
    int task_id = dt_task_create(0, task_memory_copy, args, NULL);

    // Wait for task to complete
    dt_join(task_id);

    dt_memcpy_from(buf, addr2, sizeof(buf)); // (3) Read string from addr2
    printf("Memory addr2: %s\n", buf);

    // Free memory
    dt_free(addr1);
    dt_free(addr2);
}

int main()
{
    // Distributed task initialization - must be at the very beginning of `main()` function
    dt_init();

    run_mem_simple();
    run_mem_copy();

    return 0;
}
