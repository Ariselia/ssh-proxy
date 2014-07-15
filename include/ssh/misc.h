#ifndef SSH_MISC_H
#define SSH_MISC_H

/* in misc.c */
/* gets the user home dir. */
char *ssh_get_user_home_dir(void);
char *ssh_get_local_username(void);
int ssh_file_readaccess_ok(const char *file);

char *ssh_path_expand_tilde(const char *d);
char *ssh_path_expand_escape(ssh_session_t * session, const char *s);
int ssh_analyze_banner(ssh_session_t * session, int server, int *ssh1, int *ssh2);
int ssh_is_ipaddr_v4(const char *str);
int ssh_is_ipaddr(const char *str);

#ifndef HAVE_NTOHLL
/* macro for byte ordering */
uint64_t ntohll(uint64_t);
#endif

#ifndef HAVE_HTONLL
#define htonll(x) ntohll((x))
#endif

/* list processing */

typedef struct ssh_list_struct ssh_list_t;
typedef struct ssh_iterator_struct ssh_iterator_t;

struct ssh_list_struct {
  ssh_iterator_t *root;
  ssh_iterator_t *end;
};

struct ssh_iterator_struct {
  struct ssh_iterator_struct *next;
  const void *data;
};

struct ssh_timestamp {
  long seconds;
  long useconds;
};

ssh_list_t *ssh_list_new(void);
void ssh_list_free(ssh_list_t *list);
ssh_iterator_t *ssh_list_get_iterator(const ssh_list_t *list);
ssh_iterator_t *ssh_list_find(const ssh_list_t *list, void *value);
int ssh_list_append(ssh_list_t *list, const void *data);
int ssh_list_prepend(ssh_list_t *list, const void *data);
void ssh_list_remove(ssh_list_t *list, ssh_iterator_t *iterator);
char *ssh_lowercase(const char* str);
char *ssh_hostport(const char *host, int port);

const void *_ssh_list_pop_head(ssh_list_t *list);

#define ssh_iterator_value(type, iterator)\
  ((type)((iterator)->data))

/** @brief fetch the head element of a list and remove it from list
 * @param type type of the element to return
 * @param list the ssh_list to use
 * @return the first element of the list, or NULL if the list is empty
 */
#define ssh_list_pop_head(type, ssh_list)\
  ((type)_ssh_list_pop_head(ssh_list))

int ssh_make_milliseconds(long sec, long usec);
void ssh_timestamp_init(struct ssh_timestamp *ts);
int ssh_timeout_elapsed(struct ssh_timestamp *ts, int timeout);
int ssh_timeout_update(struct ssh_timestamp *ts, int timeout);

int ssh_match_group(const char *group, const char *object);

#endif /* ! SSH_MISC_H */
