/**
 * @file mine.c
 *
 * Parallelizes the hash inversion technique used by cryptocurrencies such as
 * bitcoin.
 *
 * Input:    Number of threads, block difficulty, and block contents (string)
 * Output:   Hash inversion solution (nonce) and timing statistics.
 *
 * Compile:  (run make)
 *           When your code is ready for performance testing, you can add the
 *           -O3 flag to enable all compiler optimizations.
 *
 * Run:      ./miner 4 24 'Hello CS 521!!!'
 *
 *   Number of threads: 4
 *     Difficulty Mask: 00000000000000000000000011111111
 *          Block data: [Hello CS 521!!!]
 *
 *   ----------- Starting up miner threads!  -----------
 *
 *   Solution found by thread 3:
 *   Nonce: 10211906
 *   Hash: 0000001209850F7AB3EC055248EE4F1B032D39D0
 *   10221196 hashes in 0.26s (39312292.30 hashes/sec)
 */

#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "sha1.h"
#include "miner.h"

unsigned long long total_inversions;
volatile bool solution_found = false;
pthread_mutex_t solution_lock = PTHREAD_MUTEX_INITIALIZER;
uint64_t found_nonce = 0;
int found_thread_id = -1;
uint8_t found_digest[SHA1_HASH_SIZE];

struct thread_args_t{
    int thread_id;
    char *block_data;
    uint32_t difficulty_mask;
    uint64_t start_nonce;
    uint64_t end_nonce;
};


double get_time()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec / 1000000.0;
}

void print_binary32(uint32_t num) {
    int i;
    for (i = 31; i >= 0; --i) {
        uint32_t position = (unsigned int) 1 << i;
        printf("%c", ((num & position) == position) ? '1' : '0');
    }
    puts("");
}

uint64_t mine(char *data_block, uint32_t difficulty_mask,
        uint64_t nonce_start, uint64_t nonce_end,
        uint8_t digest[SHA1_HASH_SIZE]) {

    for (uint64_t nonce = nonce_start; nonce < nonce_end; nonce++) {
        /* A 64-bit unsigned number can be up to 20 characters  when printed: */
        size_t buf_sz = sizeof(char) * (strlen(data_block) + 20 + 1);
        char *buf = malloc(buf_sz);

        /* Create a new string by concatenating the block and nonce string.
         * For example, if we have 'Hello World!' and '10', the new string
         * is: 'Hello World!10' */
        snprintf(buf, buf_sz, "%s%lu", data_block, nonce);

        /* Hash the combined string */
        sha1sum(digest, (uint8_t *) buf, strlen(buf));
        free(buf);
        total_inversions++;

        /* Get the first 32 bits of the hash */
        uint32_t hash_front = 0;
        hash_front |= digest[0] << 24;
        hash_front |= digest[1] << 16;
        hash_front |= digest[2] << 8;
        hash_front |= digest[3];

        /* Check to see if we've found a solution to our block */
        if ((hash_front & difficulty_mask) == hash_front) {
            return nonce;
        }
    }

    return 0;
}

void *mine_worker(void *arg) {
    struct thread_args_t *args = (struct thread_args_t *)arg;

    if (solution_found) {
        return NULL;
    }

    uint8_t digest[SHA1_HASH_SIZE];
    uint64_t result = mine(args->block_data,
                           args->difficulty_mask,
                           args->start_nonce,
                           args->end_nonce,
                           digest);

    if (result != 0) {
        pthread_mutex_lock(&solution_lock);
        if (!solution_found) {
            solution_found = true;
            found_nonce = result;
            found_thread_id = args->thread_id;
            memcpy(found_digest, digest, SHA1_HASH_SIZE);
        }
        pthread_mutex_unlock(&solution_lock);
    }

    return NULL;
}

int main(int argc, char *argv[]) {

    if (argc != 4) {
        printf("Usage: %s threads difficulty 'block data (string)'\n", argv[0]);
        return EXIT_FAILURE;
    }

    int num_threads = atoi(argv[1]);
    int difficulty_bits = atoi(argv[2]);

    if (num_threads <= 0 || difficulty_bits < 1 || difficulty_bits > 32) {
        printf("Invalid input. Threads must be > 0, difficulty between 1 and 32.\n");
        return EXIT_FAILURE;
    }

    printf("Number of threads: %d\n", num_threads);

    // Generate difficulty mask dynamically based on bits (1–32)
    uint32_t difficulty_mask;
    if (difficulty_bits == 32) {
        difficulty_mask = 0;
    } else {
        uint32_t shift_amount = 32 - difficulty_bits;
        uint32_t ones = ((unsigned int) 1 << shift_amount) - 1;
        difficulty_mask = ones;
    }

    


    printf("  Difficulty Mask: ");
    print_binary32(difficulty_mask);

    /* We use the input string passed in (argv[3]) as our block data. In a
     * complete bitcoin miner implementation, the block data would be composed
     * of bitcoin transactions. */
    char *bitcoin_block_data = argv[3];
    printf("       Block data: [%s]\n", bitcoin_block_data);

    printf("\n----------- Starting up miner threads!  -----------\n\n");

    double start_time = get_time();

    pthread_t threads[num_threads];
    struct thread_args_t args[num_threads];

    uint64_t range = UINT64_MAX / num_threads;
    for (int i = 0; i < num_threads; ++i) {
        args[i].thread_id = i;
        args[i].block_data = bitcoin_block_data;
        args[i].difficulty_mask = difficulty_mask;
        args[i].start_nonce = i * range + 1;
        args[i].end_nonce = (i == num_threads - 1) ? UINT64_MAX : (i + 1) * range;

        pthread_create(&threads[i], NULL, mine_worker, &args[i]);
    }

    for (int i = 0; i < num_threads; ++i) {
        pthread_join(threads[i], NULL);
    }

    double end_time = get_time();

    if (!solution_found) {
        printf("No solution found!\n");
        return EXIT_FAILURE;
    }

    /* When printed in hex, a SHA-1 checksum will be 40 characters. */
    char solution_hash[41];
    sha1tostring(solution_hash, found_digest);

    printf("Solution found by thread %d:\n", found_thread_id);
    printf("Nonce: %llu\n", found_nonce);
    printf(" Hash: %s\n", solution_hash);

    double total_time = end_time - start_time;
    printf("%llu hashes in %.2fs (%.2f hashes/sec)\n",
           total_inversions, total_time, total_inversions / total_time);

    return 0;
}
