#include "cachelab.h"
#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <math.h>

typedef struct
{
    int hits;
    int misses;
    int evictions;
} simulate_result;

typedef struct cache_line
{
    long tag;
    struct cache_line *next;
} cache_line;

typedef struct
{
    int num_lines;
    cache_line *lines;
} cache_set;

typedef struct
{
    int s;
    int E;
    int b;
    char *t;
    cache_set *sets;
} cache_storage;

void init_cache(cache_storage *);
void access_cache(cache_storage *, simulate_result *, long);
void simulate(cache_storage *, simulate_result *, char, long);
void remove_line(cache_set *, int);
void add_line(cache_set *, long);

int main(int argc, char *argv[])
{
    cache_storage cache;
    simulate_result result = {0, 0, 0};
    int opt;
    while ((opt = getopt(argc, argv, "s:E:b:t:")) != -1)
    {
        switch (opt)
        {
        case 's':
            cache.s = atoi(optarg);
            break;
        case 'E':
            cache.E = atoi(optarg);
            break;
        case 'b':
            cache.b = atoi(optarg);
            break;
        case 't':
            cache.t = optarg;
            break;
        default:
            break;
        }
    }
    init_cache(&cache);

    char buffer[256];
    FILE *file = fopen(cache.t, "r");
    while (fgets(buffer, 256, file) != NULL)
    {
        if (buffer[0] == 'I')
        {
            continue;
        }
        char instruction = buffer[1];
        long address = strtol(buffer + 3, NULL, 16);
        simulate(&cache, &result, instruction, address);
    }
    fclose(file);

    printSummary(result.hits, result.misses, result.evictions);
    return 0;
}

void access_cache(cache_storage *cache, simulate_result *result, long address)
{
    long tag = address >> (cache->s + cache->b);
    int set_index = (address >> cache->b) & ((1 << cache->s) - 1);
    cache_set *set = &cache->sets[set_index];
    cache_line *line = set->lines;
    for (int i = 0; i < set->num_lines; i++)
    {
        if (line->tag == tag)
        {
            result->hits++;
            remove_line(set, i);
            add_line(set, tag);
            return;
        }
        line = line->next;
    }
    result->misses++;
    if (set->num_lines < cache->E)
    {
        add_line(set, tag);
        return;
    }
    result->evictions++;
    remove_line(set, cache->E - 1);
    add_line(set, tag);
}

void simulate(cache_storage *cache, simulate_result *result, char instruction, long address)
{
    switch (instruction)
    {
    case 'M':
        access_cache(cache, result, address);
    case 'L':
    case 'S':
        access_cache(cache, result, address);
        break;
    }
}

void add_line(cache_set *set, long tag)
{
    cache_line *line = malloc(sizeof(cache_line));
    line->tag = tag;
    line->next = set->lines;
    set->lines = line;
    set->num_lines++;
}

void remove_line(cache_set *set, int index)
{
    if (index == 0)
    {
        cache_line *temp = set->lines;
        set->lines = set->lines->next;
        free(temp);
        set->num_lines--;
        return;
    }

    cache_line *line = set->lines;
    for (int i = 0; i < index - 1; i++)
    {
        line = line->next;
    }
    cache_line *temp = line->next;
    line->next = line->next->next;
    free(temp);
    set->num_lines--;
}

void init_cache(cache_storage *cache)
{
    double S = pow(2, cache->s);
    cache->sets = (cache_set *)calloc(S, sizeof(cache_set));
}