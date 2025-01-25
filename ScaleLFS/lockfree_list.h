#define IN_KERNEL2 (1)

#if IN_KERNEL2
#include <linux/types.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#else
#include <stdbool.h>
#include <pthread.h>
#include <glib.h>
#include <stdio.h>
#endif

#define HASH_MODE (1)
#if HASH_MODE
#define BUCKET_CNT (32)
#endif

#define MAX_SIZE (0xFFFFFFFF)
#define ALL_RANGE (0xFFFFFFFF)

struct LNode {
  unsigned int start;
  unsigned int end;
  volatile struct LNode* next;
  unsigned int reader;
#if IN_KERNEL2
  struct rcu_head rcu;
#endif
};

struct ListRL {
#if HASH_MODE
  volatile struct LNode* head[BUCKET_CNT];
#else
  volatile struct LNode* head;
#endif
};

struct RangeLock {
#if HASH_MODE
  struct LNode* node[BUCKET_CNT];
  unsigned int bucket;
#else
  struct LNode* node;
#endif
};

struct f3fs_rwsem3 {
  struct ListRL list_rl;
};

void init_f3fs_rwsem3(struct f3fs_rwsem3* sem);
#if HASH_MODE
#else
struct RangeLock* MutexRangeAcquire(struct ListRL* list_rl,
  unsigned int start,
  unsigned int end,
  bool try);
#endif
void MutexRangeRelease(struct RangeLock* rl);

struct RangeLock* RWRangeTryAcquire(
  struct ListRL* list_rl,
  unsigned long long start,
  unsigned long long end,
  bool writer);

struct RangeLock* RWRangeAcquire(
  struct ListRL* list_rl,
  unsigned long long start,
  unsigned long long end,
  bool writer);

