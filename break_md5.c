#include <sys/types.h>
#include <openssl/md5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <zconf.h>

#define PASS_LEN 6
#define NUM_THREADS 6

#define PBSTR "==================================================================================================="
#define PBWIDTH 70

struct hash {
    char * argument[250];
    char * passwd[250];
    long cont;
    pthread_mutex_t * mutex;
    int flag;
    int pass_flags;
    int arg_length;
};

struct args {
    int thread_num;
    struct hash * hash;
    long min;
};

struct thread_info {
    pthread_t    id;        // id returned by pthread_create()
    struct args *args;      // pointer to the arguments
};

long ipow(long base, int exp)
{
    long res = 1;
    for (;;)
    {
        if (exp & 1)
            res *= base;
        exp >>= 1;
        if (!exp)
            break;
        base *= base;
    }

    return res;
}

long pass_to_long(char *str) {
    long res = 0;

    for(int i=0; i < PASS_LEN; i++)
        res = res * 26 + str[i]-'a';

    return res;
};

void long_to_pass(long n, unsigned char *str) {  // str should have size PASS_SIZE+1
    for(int i=PASS_LEN-1; i >= 0; i--) {
        str[i] = n % 26 + 'a';
        n /= 26;
    }
    str[PASS_LEN] = '\0';
}

void to_hex(unsigned char *res, char *hex_res) {
    for(int i=0; i < MD5_DIGEST_LENGTH; i++) {
        snprintf(&hex_res[i*2], 3, "%.2hhx", res[i]);
    }
    hex_res[MD5_DIGEST_LENGTH * 2] = '\0';
}

void * progress_bar(void * ptr) {
    long maximum = ipow(26, PASS_LEN);
    struct args * args = ptr;
    while (args->hash->pass_flags != 0) {
        int val_aux = (int) ((args->hash->cont * 100) / (maximum * args->hash->arg_length));
        int lpad = (int) ((args->hash->cont * PBWIDTH) / (maximum * args->hash->arg_length));
        int rpad = PBWIDTH - lpad;
        printf("\033[1;33m");
        printf("\r%3d%% [%.*s%*s]", val_aux, lpad, PBSTR, rpad, "");
        fflush(stdout);
        usleep(10000);
    }
    printf("\n");
    return NULL;
}

void * break_pass(void *md5) {
    struct args * args = md5;
    unsigned char res[MD5_DIGEST_LENGTH];
    char hex_res[MD5_DIGEST_LENGTH * 2 + 1];
    unsigned char *pass = malloc((PASS_LEN + 1) * sizeof(char));
    long bound = ipow(26, PASS_LEN); // we have passwords of PASS_LEN
    // lowercase chars =>
    //     26 ^ PASS_LEN  different cases

    for(long i = args->min; i <= (bound / NUM_THREADS) * (args->thread_num + 1); i++) {
        if (args->hash->pass_flags == 0)
            break;
        long_to_pass(i, pass);

        MD5(pass, PASS_LEN, res);

        to_hex(res, hex_res);

        pthread_mutex_lock(&args->hash->mutex[0]);
        args->hash->cont++;
        pthread_mutex_unlock(&args->hash->mutex[0]);

        for (int j = 0; j < args->hash->arg_length; ++j) {
            if(!strcmp(hex_res, args->hash->argument[j])) {
                args->hash->passwd[j] = (char *) pass;
                printf("\033[0;32m");
                printf("\n%s: %s\n", args->hash->argument[j], args->hash->passwd[j]);
                pthread_mutex_lock(&args->hash->mutex[1]);
                args->hash->flag = 1;
                args->hash->pass_flags--;
                pthread_mutex_unlock(&args->hash->mutex[1]);
            }
        }
    }


    return NULL;
}

struct thread_info * start_threads(struct hash * hash) {
    int i;
    struct thread_info * threads;

    printf("creating %d threads\n",  NUM_THREADS);
    threads = malloc(sizeof(struct thread_info) * (NUM_THREADS));

    if (threads == NULL) {
        printf("Not enough memory\n");
        exit(1);
    }

    if ((hash->mutex = malloc(2 * sizeof(pthread_mutex_t))) == NULL) {
        printf("Not enough memory\n");
        exit(1);
    }

    for (int j = 0; j < 2; ++j) {
        pthread_mutex_init(&hash->mutex[j], NULL);
    }

    for (i = 0; i < NUM_THREADS; i++) {
        threads[i].args = malloc(sizeof(struct args));
        long temp = ipow(26, PASS_LEN) / NUM_THREADS;
        threads[i].args->hash = hash;
        threads[i].args->thread_num = i;
        threads[i].args->hash->flag = 0;
        threads[i].args->min = (temp + 1) * i;


        if (i == NUM_THREADS - 1) {
            if (0 != pthread_create(&threads[i].id, NULL, progress_bar, threads[i].args)) {
                printf("Could not create thread #%d", i);
                exit(1);
            }
        }
        else {
            if (0 != pthread_create(&threads[i].id, NULL, break_pass, threads[i].args)) {
                printf("Could not create thread #%d", i);
                exit(1);
            }
        }
    }

    return threads;

}

void wait(struct thread_info *threads, struct hash * hash)
{
    for (int i = 0; i < NUM_THREADS; ++i) {
        pthread_join(threads[i].id, NULL);
    }

    for (int i = 0; i < NUM_THREADS; i++)
        free(threads[i].args);

    for (int i = 0; i < 2; ++i) {
        pthread_mutex_destroy(&hash->mutex[i]);
    }

    free(threads);
    free(hash->mutex);

}

int main(int argc, char *argv[]) {
    struct thread_info * thrs;
    struct hash hash;
    if(argc < 2) {
        printf("Use: %s string\n", argv[0]);
        exit(0);
    }

    for (int i = 1; i < argc; ++i) {
        hash.argument[i - 1] = argv[i];
    }
    for (int i = 0; i < 250; ++i) {
        hash.passwd[i] = "";
    }
    hash.cont = 0;
    hash.flag = 0;
    hash.arg_length = argc - 1;
    hash.pass_flags = hash.arg_length;

    // Create the threads
    thrs = start_threads(&hash);
    wait(thrs, &hash);
    return 0;
}
