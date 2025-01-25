#define IN_KERNEL (1)

#if IN_KERNEL
typedef struct rw_semaphore my_lock_t;
typedef void* list_arg_t;

#define print printk
#else
#include <pthread.h>
#include <glib.h>
#include <stdio.h>
#define print printf

typedef pthread_rwlock_t my_lock_t;
typedef gpointer list_arg_t;
struct lock_class_key {
  unsigned temp;
};
#endif

struct f3fs_rwsem2 {
  my_lock_t range_lock;
#if IN_KERNEL
  struct rb_root locked_ranges;
#else
  GList* locked_ranges;
#endif
};

struct f3fs_range {
  my_lock_t internal_lock;
#if IN_KERNEL
  struct rb_node node;
#endif
  unsigned start;
  unsigned size;
  unsigned ref;
  struct f3fs_rwsem2 nested;
};

#define init_f3fs_rwsem2(sem)					\
do {								\
	static struct lock_class_key __key;			\
								\
	__init_f3fs_rwsem2((sem), #sem, &__key);			\
} while (0)

static inline void _down_lock(my_lock_t* lock, bool is_write) {
#if IN_KERNEL
  if (is_write) {
    down_write(lock);
  } else {
    down_read(lock);
  }
#else
  if (is_write) {
    pthread_rwlock_wrlock(lock);
  } else {
    pthread_rwlock_rdlock(lock);
  }
#endif
}

static inline void _up_lock(my_lock_t* lock, bool is_write) {
#if IN_KERNEL
  if (is_write) {
    up_write(lock);
  } else {
    up_read(lock);
  }
#else
  pthread_rwlock_unlock(lock);
#endif
}

static inline int _down_trylock(my_lock_t* lock, bool is_write) {
#if IN_KERNEL
  if (is_write) {
    return down_write_trylock(lock);
  } else {
    return down_read_trylock(lock);
  }
#else
  if (is_write) {
    return pthread_rwlock_trywrlock(lock) == 0;
  } else {
    return pthread_rwlock_tryrdlock(lock) == 0;
  }
#endif
}

static inline void __init_f3fs_rwsem2(struct f3fs_rwsem2 *sem,
		const char *sem_name, struct lock_class_key *key)
{
#if IN_KERNEL
	__init_rwsem(&sem->range_lock, sem_name, key);
  sem->locked_ranges = RB_ROOT;
#else
  pthread_rwlock_init(&sem->range_lock, NULL);
  sem->locked_ranges = NULL;
#endif
}

static inline void check_range(list_arg_t data, list_arg_t user_data)
{
  struct f3fs_range* range = (struct f3fs_range*)data;
  void** casted_user_data = (void*)user_data;
  unsigned start = *(unsigned*)(casted_user_data[0]);
  unsigned* min_start = (unsigned*)(&casted_user_data[1]);

  if (range->start + range->size > start) {
    if (range->start < *min_start) {
      *min_start = range->start;
      casted_user_data[2] = (void*)range;
    }
  }
}

static inline
struct f3fs_range* get_min_locked_range(struct f3fs_rwsem2 *sem, unsigned start) {
  void* user_data[3];

  user_data[0] = (void*)&start;
  user_data[1] = (void*)0xFFFFFFFF; // found min_start
  user_data[2] = NULL; // found min_start_range for ret
#if IN_KERNEL
  {
    struct rb_node *node = sem->locked_ranges.rb_node;
    struct f3fs_range* ret = NULL;

    while (node) {
      struct f3fs_range *cur_range = rb_entry(node, struct f3fs_range, node);

      if (start <= cur_range->start) {
        ret = cur_range;
        node = node->rb_left;
      } else {
        node = node->rb_right;
      }
    }
    return ret;
  }
#else
  g_list_foreach(sem->locked_ranges, check_range, user_data);
#endif
  return (struct f3fs_range*)user_data[2];
}

static inline
struct f3fs_range* f3fs_alloc_range(unsigned start, unsigned size)
{
#if IN_KERNEL
  struct f3fs_range* ret = kmalloc(sizeof(struct f3fs_range), GFP_KERNEL);
  static struct lock_class_key __key;

	__init_rwsem(&ret->internal_lock, "f3fs_range_internal" , &__key);
  RB_CLEAR_NODE(&ret->node);
#else
  struct f3fs_range* ret = malloc(sizeof(struct f3fs_range));

  pthread_rwlock_init(&ret->internal_lock, NULL);
#endif
  ret->start = start;
  ret->size = size;
  ret->ref = 1;
  init_f3fs_rwsem2(&ret->nested);
  return ret;
}

static bool is_less(struct rb_node* node, const struct rb_node* parent) {
  struct f3fs_range* node_range = rb_entry(node, struct f3fs_range, node);
  struct f3fs_range* parent_range = rb_entry(parent, struct f3fs_range, node);
  if (node_range-> start < parent_range->start) {
    return true;
  } else {
    return false;
  }
}

static inline void f3fs_insert_range2(
  struct f3fs_rwsem2* head, struct f3fs_range* new_range)
{
#if IN_KERNEL
  rb_add(&new_range->node, &head->locked_ranges, is_less);
#else
  head->locked_ranges = g_list_append(head->locked_ranges, (gpointer) new_range);
#endif
//  printf("insert range %p %d %x\n", new_range, new_range->start, new_range->size);
}

static inline void f3fs_remove_range(
  struct f3fs_rwsem2* head, struct f3fs_range* del_range)
{
#if IN_KERNEL
  rb_erase(&del_range->node, &head->locked_ranges);
  kfree(del_range);
#else
  head->locked_ranges = g_list_remove(head->locked_ranges, (gpointer) del_range);
#endif
}

static inline bool check_totally_overlapped(
  struct f3fs_range* range, unsigned start, unsigned size) {
  return range->size <= size && range->start == start;
}

static inline void f3fs_up_range(
  struct f3fs_rwsem2 *sem, unsigned start, unsigned size, bool is_write)
{
  struct f3fs_range* min_range;
  //print("%s %d %p %u %u\n", __func__, __LINE__, sem, start, size);
  _down_lock(&sem->range_lock, true);
  min_range = get_min_locked_range(sem, start);
  if (min_range == NULL) {
    print("error! %s %d\n", __func__, __LINE__);
    return;
  } else if (start < min_range->start) {
    print("error! %s %d\n", __func__, __LINE__);
    return;
  } else {
    bool totally_overlapped = check_totally_overlapped(min_range, start, size);
    unsigned lock_size = min_range->size;
  //  printf("%s %d %p ref %d\n", __func__, __LINE__, sem, min_range->ref);
    min_range->ref--;
    // whole min_range is owned
    if (totally_overlapped) {
      _up_lock(&min_range->internal_lock, is_write);
    } else {
      if (min_range->size + min_range->start > start + size) {
        lock_size = size;
      } else {
        lock_size = min_range->size + min_range->start - start;
      }
      f3fs_up_range(&min_range->nested, start, lock_size, is_write);
      _up_lock(&min_range->internal_lock, false);
    }
    start += lock_size;
    size -= lock_size;

    if (min_range->ref == 0) {
      f3fs_remove_range(sem, min_range);
    }
  }
  _up_lock(&sem->range_lock, true);
  if (size > 0) {
    f3fs_up_range(sem, start, size, is_write);
  }
}

static inline int f3fs_down_range_trylock(
  struct f3fs_rwsem2 *sem, unsigned start, unsigned size, bool is_write)
{
  struct f3fs_range* min_range;
  bool overlapped = false;
  bool totally_overlapped = false;
  unsigned nested_start, nested_size;
  bool not_overlapped = true;
  bool locked = true;
  unsigned orig_start = start;
  unsigned locked_size = 0;
//  print("%s %d %p %u %u\n", __func__, __LINE__, sem, start, size);

  _down_lock(&sem->range_lock, true);
  min_range = get_min_locked_range(sem, start);
 
  not_overlapped = min_range == NULL || min_range->start > start; 
  if (not_overlapped) {
    unsigned lock_size = size;
    struct f3fs_range* new_range;
    if (min_range != NULL) {
      if (min_range->start < start + size) {
        lock_size = min_range->start - start;
      }
    }
    new_range = f3fs_alloc_range(start, lock_size);
    f3fs_insert_range2(sem, new_range);
    // new write should be acquired
    _down_lock(&new_range->internal_lock, is_write);
    start += lock_size;
    size -= lock_size;
    locked_size += lock_size;
  }

  if (size > 0) {
      unsigned min_range_end = min_range->start + min_range->size;
   //   print("%s %d %p %u %u\n", __func__, __LINE__, sem, start, size);
      overlapped = start >= min_range->start && min_range_end > start;
      if (overlapped) {
        nested_size = size;
        nested_start = start;
        totally_overlapped = check_totally_overlapped(min_range, start, size);
        min_range->ref++;
        if (totally_overlapped) {
          nested_size = min_range->size;
        } else {
          bool not_fit_end = min_range_end < start + size;
          if (not_fit_end) {
            nested_size = min_range_end - start;
          }
        }

        start += nested_size;
        size -= nested_size;
    }
  }
  //print("%s %d %p %u %u\n", __func__, __LINE__, sem, start, size);

  _up_lock(&sem->range_lock, true);

  if (overlapped) {
    if (totally_overlapped) {
      locked = _down_trylock(&min_range->internal_lock, is_write);
      if (!locked) {
        if (locked_size > 0) {
          f3fs_up_range(sem, orig_start, locked_size, is_write);
        }
      //  print("%s %d %p %u %u\n", __func__, __LINE__, sem, start, size);
        return false;
      }
    } else {
      // down_read to make partially overlapped threads can access simultaneously
      locked = _down_trylock(&min_range->internal_lock, false);
      if (!locked) {
        if (locked_size > 0) {
          f3fs_up_range(sem, orig_start, locked_size, is_write);
        }
    //    print("%s %d %p %u %u\n", __func__, __LINE__, sem, start, size);
        return false;
      }
      locked = f3fs_down_range_trylock(
        &min_range->nested, nested_start, nested_size, is_write);
      if (!locked) {
        _up_lock(&min_range->internal_lock, false);
        if (locked_size > 0) {
          f3fs_up_range(sem, orig_start, locked_size, is_write);
        }
  //      print("%s %d %p %u %u\n", __func__, __LINE__, sem, start, size);
        return false;
      }
    }

    locked_size += nested_size;
  }

  if (size > 0) {
    locked = f3fs_down_range_trylock(sem, start, size, is_write);
    if (!locked) {
      f3fs_up_range(sem, orig_start, locked_size, is_write);
    }
  }
//  print("%p locked %d\n", sem, locked);
  return locked;
}

static inline void f3fs_down_range(
  struct f3fs_rwsem2 *sem, unsigned start, unsigned size, bool is_write)
{
  struct f3fs_range* min_range;
  bool overlapped = false;
  bool totally_overlapped = false;
  unsigned nested_start, nested_size;
  bool not_overlapped = true;

//  print("%s %d %p %u %u\n", __func__, __LINE__, sem, start, size);
  _down_lock(&sem->range_lock, true);
  min_range = get_min_locked_range(sem, start);
 
  not_overlapped = min_range == NULL || min_range->start > start; 
  if (not_overlapped) {
    unsigned lock_size = size;
    struct f3fs_range* new_range;
    if (min_range != NULL) {
      if (min_range->start < start + size) {
        lock_size = min_range->start - start;
      }
    }
    new_range = f3fs_alloc_range(start, lock_size);
    f3fs_insert_range2(sem, new_range);
    _down_lock(&new_range->internal_lock, is_write);
    start += lock_size;
    size -= lock_size;
  }

  if (size > 0) {
      unsigned min_range_end = min_range->start + min_range->size;
      overlapped = start >= min_range->start && min_range_end > start;
      if (overlapped) {
        nested_size = size;
        nested_start = start;
        totally_overlapped = check_totally_overlapped(min_range, start, size);
        min_range->ref++;
        //printf("%s %d %p ref %d\n", __func__, __LINE__, sem, min_range->ref);
        if (totally_overlapped) {
          nested_size = min_range->size;
        } else {
          bool not_fit_end = min_range_end < start + size;
          if (not_fit_end) {
            nested_size = min_range_end - start;
          }
        }

        start += nested_size;
        size -= nested_size;
    }
  }

  _up_lock(&sem->range_lock, true);

  if (overlapped) {
    if (totally_overlapped) {
    //printf("overlapped? %u %u %u\n", overlapped, start, size);
      _down_lock(&min_range->internal_lock, is_write);
    } else {
      // down_read to make partially overlapped threads can access simultaneously
    //printf(" 22 overlapped? %u %u %u\n", overlapped, start, size);
      _down_lock(&min_range->internal_lock, false);
      f3fs_down_range(&min_range->nested, nested_start, nested_size, is_write);
    }
  }

  if (size > 0) {
    f3fs_down_range(sem, start, size, is_write);
  }
}

