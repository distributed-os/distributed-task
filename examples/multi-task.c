#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include "dtt.h"

struct sum_operands {
    int a;
    int b;
};

void sum_task(dt_buf_t *args, dt_buf_t *ret)
{
    struct sum_operands *input = (struct sum_operands *)args->data;
    int *sum_result = (int *)ret->data;

    usleep(rand() % 1000000);

    *sum_result = input->a + input->b;

    printf("sum task call, input: %d %d ret: %d ...\n", input->a, input->b, *sum_result);
}

DT_DECLARE_TASK(sum_task);

void square_task(dt_buf_t *args, dt_buf_t *ret)
{
    int *input = (int *)args->data;
    int *out = (int *)ret->data;

    usleep(rand() % 1000000);

    *out = (*input) * (*input);

    printf("square task call, input: %d ret: %d ...\n", *input, *out);
}

DT_DECLARE_TASK(square_task);

int run_sum_task()
{
    int32_t task_id = 0;

    int result;
    struct sum_operands operands;
    dt_buf_t args = { .len = sizeof(struct sum_operands), .data = NULL };
    dt_buf_t ret = { .len = sizeof(int), .data = NULL };

    operands.a = rand() % 100;
    operands.b = rand() % 1000;
    ret.data = (char *)(&result);
    args.data = (char *)(&operands);

    // Create distributed task
    task_id = dt_task_create(0, sum_task, &args, &ret);

    // Wait for task completion and retrieve result
    dt_join(task_id);

    printf("sum is: %d ?= %d \n", result, operands.a + operands.b);

    return 0;
}

int run_square_tasks()
{
    int numbers[5] = {1, 2, 3, 4, 5};
    int sum = 0;
    int32_t task_ids[5] = {0};

    dt_buf_t args = { .len = sizeof(int), .data = NULL };
    dt_buf_t results[5] = { 0 };

    for (int i = 0; i < 5; i++) {
        results[i].len = sizeof(int);
        results[i].data = calloc(1, sizeof(int));
    }

    for (int i = 0; i < 5; i++) {
        // Create distributed task
        args.data = (char *)(numbers + i);
        task_ids[i] = dt_task_create(0, square_task, &args, results + i);
    }

    for (int i = 0; i < 5; i++) {
        // Wait for task completion and retrieve result
        dt_join(task_ids[i]);
    }

    for (int i = 0; i < 5; i++) {
        sum += *(int *)(results[i].data);
    }

    printf("sum of squares 1~5 is 55 ?= %d \n", sum);

    // Free allocated memory
    for (int i = 0; i < 5; i++) {
        free(results[i].data);
    }

    return 0;
}

int main()
{
    srand(time(NULL) + getpid());

    // Initialize distributed task system, must be called at the very beginning of `main()`
    dt_init();

    run_sum_task();      // Calculate sum of two random numbers
    run_square_tasks();  // Calculate sum of squares from 1 to 5

    return 0;
}
