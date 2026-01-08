#ifndef __LIST_H__
#define __LIST_H__

#include <stdio.h>
#include <stdlib.h>

struct list_head {
    struct list_head *prev;
    struct list_head *next;
};

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define LIST_HEAD(name) \
    struct list_head name = LIST_HEAD_INIT(name)

static inline void INIT_LIST_HEAD(struct list_head *list) {
    list->next = list;
    list->prev = list;
}

static inline void list_add(struct list_head *new, struct list_head *head) {
    new->next = head->next;
    new->prev = head;
    head->next->prev = new;
    head->next = new;
}

static inline void list_add_tail(struct list_head *new, struct list_head *head) {
    new->next = head;
    new->prev = head->prev;
    head->prev->next = new;
    head->prev = new;
}

static inline void list_del(struct list_head *entry) {
    entry->prev->next = entry->next;
    entry->next->prev = entry->prev;
    entry->next = NULL;
    entry->prev = NULL;
}

static inline int list_empty(const struct list_head *head) {
    return head->next == head;
}

#define list_for_each(pos, head) \
    for (pos = (head)->next; pos != (head); pos = pos->next)

#define list_for_each_safe(pos, n, head) \
    for (pos = (head)->next, n = pos->next; pos != (head); pos = n, n = pos->next)

#define list_entry(ptr, type, member) \
    ((type *)((char *)(ptr) - (unsigned long)(&((type *)0)->member)))

/**
struct my_data {
    int value;
    struct list_head list;
};

int main() {
    LIST_HEAD(my_list);

    struct my_data *data1 = malloc(sizeof(struct my_data));
    data1->value = 10;
    INIT_LIST_HEAD(&data1->list);

    struct my_data *data2 = malloc(sizeof(struct my_data));
    data2->value = 20;
    INIT_LIST_HEAD(&data2->list);

    struct my_data *data3 = malloc(sizeof(struct my_data));
    data3->value = 30;
    INIT_LIST_HEAD(&data3->list);

    list_add_tail(&data1->list, &my_list);
    list_add_tail(&data2->list, &my_list);
    list_add_tail(&data3->list, &my_list);

    struct list_head *pos, *n;
    list_for_each(pos, &my_list) {
        struct my_data *entry = list_entry(pos, struct my_data, list);
        printf("Value: %d\n", entry->value);
    }

    list_del(&data2->list);
    free(data2);

    printf("After deletion:\n");
    list_for_each(pos, &my_list) {
        struct my_data *entry = list_entry(pos, struct my_data, list);
        printf("Value: %d\n", entry->value);
    }

    list_for_each_safe(pos, n, &my_list) {
        struct my_data *entry = list_entry(pos, struct my_data, list);
        list_del(&entry->list);
        free(entry);
    }

    return 0;
}
*/

#endif