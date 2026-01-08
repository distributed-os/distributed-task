#include <stdio.h>
#include "dtt.h"

int main()
{
    // Distributed task initialization, should be called at the very beginning of the `main()` function
    dt_init();

    // Create a task
    int id = dt_cmd_create(0, "echo world >> /tmp/hello.txt", NULL);
    // Wait for the task to finish
    dt_join(id);

    printf("append world to /tmp/hello.txt\n");

    return 0;
}
