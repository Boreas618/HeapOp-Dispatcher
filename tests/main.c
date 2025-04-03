#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define N (32 * 1024 * 1024)
#define REPEAT (10000000)
#define KEYLEN (8)
#define VALLEN (128)
#define HOTBASE (18 * 1024 * 1024)
#define HOTLEN (512 * 1024)

typedef struct Node {
    char* key;
    char* value;
} Node;

char random_char() {
    const char charset[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    return charset[rand() % (sizeof(charset) - 1)];
}

void random_string(char* str, size_t len) {
    for (size_t i = 0; i < len - 1; ++i) {
        str[i] = random_char();
    }
    str[len - 1] = '\0';
}

Node** create_array(size_t size) {
    Node** array = (Node**)malloc(size * sizeof(Node*));
    for (size_t i = 0; i < size; ++i) {
        array[i] = (Node*)malloc(sizeof(Node));
    }

    for (size_t i = 0; i < size; ++i) {
        array[i]->key = (char*)malloc(KEYLEN);
        array[i]->value = (char*)malloc(VALLEN);

        if ((rand() % 100) == 0) {
            strncpy(array[i]->key, "1234567", KEYLEN);
            array[i]->key[KEYLEN - 1] = '\0';
        } else {
            random_string(array[i]->key, KEYLEN);
        }

        random_string(array[i]->value, VALLEN);
    }

    return array;
}

void free_array(Node** array, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        free(array[i]->key);
        free(array[i]->value);
        free(array[i]);
    }
    free(array);
}

double benchmark(Node** array) {
    struct timespec start_time, end_time;
    static char res[VALLEN];
    uint64_t hit_count = 0;

    clock_gettime(CLOCK_MONOTONIC, &start_time);
    for (size_t i = 0; i < REPEAT; i++) {
        int selector_1 = rand() % 100;
        int index = 0;
        if (selector_1 > 40) {
            int selector_2 = rand() % HOTLEN;
            index = HOTBASE + selector_2;
        } else {
            int selector_3 = rand() % N;
            index = selector_3;
        }
        Node* p = array[index];
        if (strcmp(p->key, "1234567") == 0) {
            hit_count += 1;
        }
        strcpy(res, p->value);
    }
    clock_gettime(CLOCK_MONOTONIC, &end_time);

    printf("hit count: %ld\n", hit_count);

    double elapsed_ns = (end_time.tv_sec - start_time.tv_sec) * 1e9 +
                        (end_time.tv_nsec - start_time.tv_nsec);
    return elapsed_ns / REPEAT;
}

int main() {
    Node** array = create_array(N);
    double avg_latency_ns = benchmark(array);
    printf("%lf\n", avg_latency_ns);
    free_array(array, N);
    return 0;
}
