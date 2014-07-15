#ifndef SSH_SFTP_H
#define SSH_SFTP_H

#include <sys/types.h>

#include "ssh-api.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
#ifndef uid_t
  typedef uint32_t uid_t;
#endif /* uid_t */
#ifndef gid_t
  typedef uint32_t gid_t;
#endif /* gid_t */
#ifdef _MSC_VER
#ifndef ssize_t
  typedef _W64 SSIZE_T ssize_t;
#endif /* ssize_t */
#endif /* _MSC_VER */
#endif /* _WIN32 */

#define LIBSFTP_VERSION 3

typedef struct sftp_attributes_struct      sftp_attributes_t;
typedef struct sftp_client_message_struct sftp_client_message_t;
typedef struct sftp_dir_struct             sftp_dir_t;
typedef struct sftp_ext_struct             sftp_ext_t;
typedef struct sftp_file_struct            sftp_file_t;
typedef struct sftp_message_struct         sftp_message_t;
typedef struct sftp_packet_struct          sftp_packet_t;
typedef struct sftp_request_queue_struct   sftp_request_queue_t;
typedef struct sftp_session_struct         sftp_session_t;
typedef struct sftp_status_message_struct  sftp_status_message_t;
typedef struct sftp_statvfs_struct*        sftp_statvfs_t;

struct sftp_session_struct {
    ssh_session_t * session;
    ssh_channel_t * channel;
    int server_version;
    int client_version;
    int version;
    sftp_request_queue_t *queue;
    uint32_t id_counter;
    int errnum;
    void **handles;
    sftp_ext_t *ext;
};

struct sftp_packet_struct {
    sftp_session_t *sftp;
    uint8_t type;
    ssh_buffer_t * payload;
};

/* file handler */
struct sftp_file_struct {
    sftp_session_t *sftp;
    char *name;
    uint64_t offset;
    ssh_string_t * handle;
    int eof;
    int nonblocking;
};

struct sftp_dir_struct {
    sftp_session_t *sftp;
    char *name;
    ssh_string_t * handle; /* handle to directory */
    ssh_buffer_t * buffer; /* contains raw attributes from server which haven't been parsed */
    uint32_t count; /* counts the number of following attributes structures into buffer */
    int eof; /* end of directory listing */
};

struct sftp_message_struct {
    sftp_session_t *sftp;
    uint8_t packet_type;
    ssh_buffer_t * payload;
    uint32_t id;
};

/* this is a bunch of all data that could be into a message */
struct sftp_client_message_struct {
    sftp_session_t *sftp;
    uint8_t type;
    uint32_t id;
    char *filename; /* can be "path" */
    uint32_t flags;
    sftp_attributes_t *attr;
    ssh_string_t * handle;
    uint64_t offset;
    uint32_t len;
    int attr_num;
    ssh_buffer_t * attrbuf; /* used by sftp_reply_attrs */
    ssh_string_t * data; /* can be newpath of rename() */
    ssh_buffer_t * complete_message; /* complete message in case of retransmission*/
    char *str_data; /* cstring version of data */
};

struct sftp_request_queue_struct {
    sftp_request_queue_t *next;
    sftp_message_t *message;
};

/* SSH_FXP_MESSAGE described into .7 page 26 */
struct sftp_status_message_struct {
	uint32_t id;
	uint32_t status;
    ssh_string_t * error;
    ssh_string_t * lang;
    char *errormsg;
    char *langmsg;
};

struct sftp_attributes_struct {
    char *name;
    char *longname; /* ls -l output on openssh, not reliable else */
    uint32_t flags;
    uint8_t type;
    uint64_t size;
    uint32_t uid;
    uint32_t gid;
    char *owner; /* set if openssh and version 4 */
    char *group; /* set if openssh and version 4 */
    uint32_t permissions;
    uint64_t atime64;
    uint32_t atime;
    uint32_t atime_nseconds;
    uint64_t createtime;
    uint32_t createtime_nseconds;
    uint64_t mtime64;
    uint32_t mtime;
    uint32_t mtime_nseconds;
    ssh_string_t * acl;
    uint32_t extended_count;
    ssh_string_t * extended_type;
    ssh_string_t * extended_data;
};

/**
 * @brief SFTP statvfs structure.
 */
struct sftp_statvfs_struct {
  uint64_t f_bsize;   /** file system block size */
  uint64_t f_frsize;  /** fundamental fs block size */
  uint64_t f_blocks;  /** number of blocks (unit f_frsize) */
  uint64_t f_bfree;   /** free blocks in file system */
  uint64_t f_bavail;  /** free blocks for non-root */
  uint64_t f_files;   /** total file inodes */
  uint64_t f_ffree;   /** free file inodes */
  uint64_t f_favail;  /** free file inodes for to non-root */
  uint64_t f_fsid;    /** file system id */
  uint64_t f_flag;    /** bit mask of f_flag values */
  uint64_t f_namemax; /** maximum filename length */
};

/**
 * @brief Start a new sftp session.
 *
 * @param session       The ssh session to use.
 *
 * @return              A new sftp session or NULL on error.
 *
 * @see sftp_free()
 */
SSH_API sftp_session_t *sftp_new(ssh_session_t * session);

/**
 * @brief Start a new sftp session with an existing channel.
 *
 * @param session       The ssh session to use.
 * @param channel		An open session channel with subsystem already allocated
 *
 * @return              A new sftp session or NULL on error.
 *
 * @see sftp_free()
 */
SSH_API sftp_session_t *sftp_new_channel(ssh_session_t * session, ssh_channel_t * channel);


/**
 * @brief Close and deallocate a sftp session.
 *
 * @param sftp          The sftp session handle to free.
 */
SSH_API void sftp_free(sftp_session_t *sftp);

/**
 * @brief Initialize the sftp session with the server.
 *
 * @param sftp          The sftp session to initialize.
 *
 * @return              0 on success, < 0 on error with ssh error set.
 *
 * @see sftp_new()
 */
SSH_API int sftp_init(sftp_session_t *sftp);

/**
 * @brief Get the last sftp error.
 *
 * Use this function to get the latest error set by a posix like sftp function.
 *
 * @param sftp          The sftp session where the error is saved.
 *
 * @return              The saved error (see server responses), < 0 if an error
 *                      in the function occured.
 *
 * @see Server responses
 */
SSH_API int sftp_get_error(sftp_session_t *sftp);

/**
 * @brief Get the count of extensions provided by the server.
 *
 * @param  sftp         The sftp session to use.
 *
 * @return The count of extensions provided by the server, 0 on error or
 *         not available.
 */
SSH_API unsigned int sftp_extensions_get_count(sftp_session_t *sftp);

/**
 * @brief Get the name of the extension provided by the server.
 *
 * @param  sftp         The sftp session to use.
 *
 * @param  indexn        The index number of the extension name you want.
 *
 * @return              The name of the extension.
 */
SSH_API const char *sftp_extensions_get_name(sftp_session_t *sftp, unsigned int indexn);

/**
 * @brief Get the data of the extension provided by the server.
 *
 * This is normally the version number of the extension.
 *
 * @param  sftp         The sftp session to use.
 *
 * @param  indexn        The index number of the extension data you want.
 *
 * @return              The data of the extension.
 */
SSH_API const char *sftp_extensions_get_data(sftp_session_t *sftp, unsigned int indexn);

/**
 * @brief Check if the given extension is supported.
 *
 * @param  sftp         The sftp session to use.
 *
 * @param  name         The name of the extension.
 *
 * @param  data         The data of the extension.
 *
 * @return 1 if supported, 0 if not.
 *
 * Example:
 *
 * @code
 * sftp_extension_supported(sftp, "statvfs@openssh.com", "2");
 * @endcode
 */
SSH_API int sftp_extension_supported(sftp_session_t *sftp, const char *name,
    const char *data);

/**
 * @brief Open a directory used to obtain directory entries.
 *
 * @param session       The sftp session handle to open the directory.
 * @param path          The path of the directory to open.
 *
 * @return              A sftp directory handle or NULL on error with ssh and
 *                      sftp error set.
 *
 * @see                 sftp_readdir
 * @see                 sftp_closedir
 */
SSH_API sftp_dir_t * sftp_opendir(sftp_session_t *session, const char *path);

/**
 * @brief Get a single file attributes structure of a directory.
 *
 * @param session      The sftp session handle to read the directory entry.
 * @param dir          The opened sftp directory handle to read from.
 *
 * @return             A file attribute structure or NULL at the end of the
 *                     directory.
 *
 * @see                sftp_opendir()
 * @see                sftp_attribute_free()
 * @see                sftp_closedir()
 */
SSH_API sftp_attributes_t *sftp_readdir(sftp_session_t *session, sftp_dir_t *dir);

/**
 * @brief Tell if the directory has reached EOF (End Of File).
 *
 * @param dir           The sftp directory handle.
 *
 * @return              1 if the directory is EOF, 0 if not.
 *
 * @see                 sftp_readdir()
 */
SSH_API int sftp_dir_eof(sftp_dir_t *dir);

/**
 * @brief Get information about a file or directory.
 *
 * @param session       The sftp session handle.
 * @param path          The path to the file or directory to obtain the
 *                      information.
 *
 * @return              The sftp attributes structure of the file or directory,
 *                      NULL on error with ssh and sftp error set.
 *
 * @see sftp_get_error()
 */
SSH_API sftp_attributes_t *sftp_stat(sftp_session_t *session, const char *path);

/**
 * @brief Get information about a file or directory.
 *
 * Identical to sftp_stat, but if the file or directory is a symbolic link,
 * then the link itself is stated, not the file that it refers to.
 *
 * @param session       The sftp session handle.
 * @param path          The path to the file or directory to obtain the
 *                      information.
 *
 * @return              The sftp attributes structure of the file or directory,
 *                      NULL on error with ssh and sftp error set.
 *
 * @see sftp_get_error()
 */
SSH_API sftp_attributes_t *sftp_lstat(sftp_session_t *session, const char *path);

/**
 * @brief Get information about a file or directory from a file handle.
 *
 * @param file          The sftp file handle to get the stat information.
 *
 * @return              The sftp attributes structure of the file or directory,
 *                      NULL on error with ssh and sftp error set.
 *
 * @see sftp_get_error()
 */
SSH_API sftp_attributes_t *sftp_fstat(sftp_file_t *file);

/**
 * @brief Free a sftp attribute structure.
 *
 * @param file          The sftp attribute structure to free.
 */
SSH_API void sftp_attributes_free(sftp_attributes_t *file);

/**
 * @brief Close a directory handle opened by sftp_opendir().
 *
 * @param dir           The sftp directory handle to close.
 *
 * @return              Returns SSH_NO_ERROR or SSH_ERROR if an error occured.
 */
SSH_API int sftp_closedir(sftp_dir_t *dir);

/**
 * @brief Close an open file handle.
 *
 * @param file          The open sftp file handle to close.
 *
 * @return              Returns SSH_NO_ERROR or SSH_ERROR if an error occured.
 *
 * @see                 sftp_open()
 */
SSH_API int sftp_close(sftp_file_t *file);

/**
 * @brief Open a file on the server.
 *
 * @param session       The sftp session handle.
 *
 * @param file          The file to be opened.
 *
 * @param accesstype    Is one of O_RDONLY, O_WRONLY or O_RDWR which request
 *                      opening  the  file  read-only,write-only or read/write.
 *                      Acesss may also be bitwise-or'd with one or  more of
 *                      the following:
 *                      O_CREAT - If the file does not exist it will be
 *                      created.
 *                      O_EXCL - When  used with O_CREAT, if the file already
 *                      exists it is an error and the open will fail.
 *                      O_TRUNC - If the file already exists it will be
 *                      truncated.
 *
 * @param mode          Mode specifies the permissions to use if a new file is
 *                      created.  It  is  modified  by  the process's umask in
 *                      the usual way: The permissions of the created file are
 *                      (mode & ~umask)
 *
 * @return              A sftp file handle, NULL on error with ssh and sftp
 *                      error set.
 *
 * @see sftp_get_error()
 */
SSH_API sftp_file_t *sftp_open(sftp_session_t *session, const char *file, int accesstype,
    mode_t mode);

/**
 * @brief Make the sftp communication for this file handle non blocking.
 *
 * @param[in]  handle   The file handle to set non blocking.
 */
SSH_API void sftp_file_set_nonblocking(sftp_file_t *handle);

/**
 * @brief Make the sftp communication for this file handle blocking.
 *
 * @param[in]  handle   The file handle to set blocking.
 */
SSH_API void sftp_file_set_blocking(sftp_file_t *handle);

/**
 * @brief Read from a file using an opened sftp file handle.
 *
 * @param file          The opened sftp file handle to be read from.
 *
 * @param buf           Pointer to buffer to recieve read data.
 *
 * @param count         Size of the buffer in bytes.
 *
 * @return              Number of bytes written, < 0 on error with ssh and sftp
 *                      error set.
 *
 * @see sftp_get_error()
 */
SSH_API ssize_t sftp_read(sftp_file_t * file, void *buf, size_t count);

/**
 * @brief Start an asynchronous read from a file using an opened sftp file handle.
 *
 * Its goal is to avoid the slowdowns related to the request/response pattern
 * of a synchronous read. To do so, you must call 2 functions:
 *
 * sftp_async_read_begin() and sftp_async_read().
 *
 * The first step is to call sftp_async_read_begin(). This function returns a
 * request identifier. The second step is to call sftp_async_read() using the
 * returned identifier.
 *
 * @param file          The opened sftp file handle to be read from.
 *
 * @param len           Size to read in bytes.
 *
 * @return              An identifier corresponding to the sent request, < 0 on
 *                      error.
 *
 * @warning             When calling this function, the internal offset is
 *                      updated corresponding to the len parameter.
 *
 * @warning             A call to sftp_async_read_begin() sends a request to
 *                      the server. When the server answers, libssh allocates
 *                      memory to store it until sftp_async_read() is called.
 *                      Not calling sftp_async_read() will lead to memory
 *                      leaks.
 *
 * @see                 sftp_async_read()
 * @see                 sftp_open()
 */
SSH_API int sftp_async_read_begin(sftp_file_t * file, uint32_t len);

/**
 * @brief Wait for an asynchronous read to complete and save the data.
 *
 * @param file          The opened sftp file handle to be read from.
 *
 * @param data          Pointer to buffer to recieve read data.
 *
 * @param len           Size of the buffer in bytes. It should be bigger or
 *                      equal to the length parameter of the
 *                      sftp_async_read_begin() call.
 *
 * @param id            The identifier returned by the sftp_async_read_begin()
 *                      function.
 *
 * @return              Number of bytes read, 0 on EOF, SSH_ERROR if an error
 *                      occured, SSH_AGAIN if the file is opened in nonblocking
 *                      mode and the request hasn't been executed yet.
 *
 * @warning             A call to this function with an invalid identifier
 *                      will never return.
 *
 * @see sftp_async_read_begin()
 */
SSH_API int sftp_async_read(sftp_file_t * file, void *data, uint32_t len, uint32_t id);

/**
 * @brief Write to a file using an opened sftp file handle.
 *
 * @param file          Open sftp file handle to write to.
 *
 * @param buf           Pointer to buffer to write data.
 *
 * @param count         Size of buffer in bytes.
 *
 * @return              Number of bytes written, < 0 on error with ssh and sftp
 *                      error set.
 *
 * @see                 sftp_open()
 * @see                 sftp_read()
 * @see                 sftp_close()
 */
SSH_API ssize_t sftp_write(sftp_file_t * file, const void *buf, size_t count);

/**
 * @brief Seek to a specific location in a file.
 *
 * @param file         Open sftp file handle to seek in.
 *
 * @param new_offset   Offset in bytes to seek.
 *
 * @return             0 on success, < 0 on error.
 */
SSH_API int sftp_seek(sftp_file_t * file, uint32_t new_offset);

/**
 * @brief Seek to a specific location in a file. This is the
 * 64bit version.
 *
 * @param file         Open sftp file handle to seek in.
 *
 * @param new_offset   Offset in bytes to seek.
 *
 * @return             0 on success, < 0 on error.
 */
SSH_API int sftp_seek64(sftp_file_t * file, uint64_t new_offset);

/**
 * @brief Report current byte position in file.
 *
 * @param file          Open sftp file handle.
 *
 * @return              The offset of the current byte relative to the beginning
 *                      of the file associated with the file descriptor. < 0 on
 *                      error.
 */
SSH_API unsigned long sftp_tell(sftp_file_t * file);

/**
 * @brief Report current byte position in file.
 *
 * @param file          Open sftp file handle.
 *
 * @return              The offset of the current byte relative to the beginning
 *                      of the file associated with the file descriptor. < 0 on
 *                      error.
 */
SSH_API uint64_t sftp_tell64(sftp_file_t * file);

/**
 * @brief Rewinds the position of the file pointer to the beginning of the
 * file.
 *
 * @param file          Open sftp file handle.
 */
SSH_API void sftp_rewind(sftp_file_t * file);

/**
 * @brief Unlink (delete) a file.
 *
 * @param sftp          The sftp session handle.
 *
 * @param file          The file to unlink/delete.
 *
 * @return              0 on success, < 0 on error with ssh and sftp error set.
 *
 * @see sftp_get_error()
 */
SSH_API int sftp_unlink(sftp_session_t *sftp, const char *file);

/**
 * @brief Remove a directoy.
 *
 * @param sftp          The sftp session handle.
 *
 * @param directory     The directory to remove.
 *
 * @return              0 on success, < 0 on error with ssh and sftp error set.
 *
 * @see sftp_get_error()
 */
SSH_API int sftp_rmdir(sftp_session_t *sftp, const char *directory);

/**
 * @brief Create a directory.
 *
 * @param sftp          The sftp session handle.
 *
 * @param directory     The directory to create.
 *
 * @param mode          Specifies the permissions to use. It is modified by the
 *                      process's umask in the usual way:
 *                      The permissions of the created file are (mode & ~umask)
 *
 * @return              0 on success, < 0 on error with ssh and sftp error set.
 *
 * @see sftp_get_error()
 */
SSH_API int sftp_mkdir(sftp_session_t *sftp, const char *directory, mode_t mode);

/**
 * @brief Rename or move a file or directory.
 *
 * @param sftp          The sftp session handle.
 *
 * @param original      The original url (source url) of file or directory to
 *                      be moved.
 *
 * @param newname       The new url (destination url) of the file or directory
 *                      after the move.
 *
 * @return              0 on success, < 0 on error with ssh and sftp error set.
 *
 * @see sftp_get_error()
 */
SSH_API int sftp_rename(sftp_session_t *sftp, const char *original, const  char *newname);

/**
 * @brief Set file attributes on a file, directory or symbolic link.
 *
 * @param sftp          The sftp session handle.
 *
 * @param file          The file which attributes should be changed.
 *
 * @param attr          The file attributes structure with the attributes set
 *                      which should be changed.
 *
 * @return              0 on success, < 0 on error with ssh and sftp error set.
 *
 * @see sftp_get_error()
 */
SSH_API int sftp_setstat(sftp_session_t *sftp, const char *file, sftp_attributes_t *attr);

/**
 * @brief Change the file owner and group
 *
 * @param sftp          The sftp session handle.
 *
 * @param file          The file which owner and group should be changed.
 *
 * @param owner         The new owner which should be set.
 *
 * @param group         The new group which should be set.
 *
 * @return              0 on success, < 0 on error with ssh and sftp error set.
 *
 * @see sftp_get_error()
 */
SSH_API int sftp_chown(sftp_session_t *sftp, const char *file, uid_t owner, gid_t group);

/**
 * @brief Change permissions of a file
 *
 * @param sftp          The sftp session handle.
 *
 * @param file          The file which owner and group should be changed.
 *
 * @param mode          Specifies the permissions to use. It is modified by the
 *                      process's umask in the usual way:
 *                      The permissions of the created file are (mode & ~umask)
 *
 * @return              0 on success, < 0 on error with ssh and sftp error set.
 *
 * @see sftp_get_error()
 */
SSH_API int sftp_chmod(sftp_session_t *sftp, const char *file, mode_t mode);

/**
 * @brief Change the last modification and access time of a file.
 *
 * @param sftp          The sftp session handle.
 *
 * @param file          The file which owner and group should be changed.
 *
 * @param times         A timeval structure which contains the desired access
 *                      and modification time.
 *
 * @return              0 on success, < 0 on error with ssh and sftp error set.
 *
 * @see sftp_get_error()
 */
SSH_API int sftp_utimes(sftp_session_t *sftp, const char *file, const struct timeval *times);

/**
 * @brief Create a symbolic link.
 *
 * @param  sftp         The sftp session handle.
 *
 * @param  target       Specifies the target of the symlink.
 *
 * @param  dest         Specifies the path name of the symlink to be created.
 *
 * @return              0 on success, < 0 on error with ssh and sftp error set.
 *
 * @see sftp_get_error()
 */
SSH_API int sftp_symlink(sftp_session_t *sftp, const char *target, const char *dest);

/**
 * @brief Read the value of a symbolic link.
 *
 * @param  sftp         The sftp session handle.
 *
 * @param  path         Specifies the path name of the symlink to be read.
 *
 * @return              The target of the link, NULL on error.
 *
 * @see sftp_get_error()
 */
SSH_API char *sftp_readlink(sftp_session_t *sftp, const char *path);

/**
 * @brief Get information about a mounted file system.
 *
 * @param  sftp         The sftp session handle.
 *
 * @param  path         The pathname of any file within the mounted file system.
 *
 * @return A statvfs structure or NULL on error.
 *
 * @see sftp_get_error()
 */
SSH_API sftp_statvfs_t sftp_statvfs(sftp_session_t *sftp, const char *path);

/**
 * @brief Get information about a mounted file system.
 *
 * @param  file         An opened file.
 *
 * @return A statvfs structure or NULL on error.
 *
 * @see sftp_get_error()
 */
SSH_API sftp_statvfs_t sftp_fstatvfs(sftp_file_t *file);

/**
 * @brief Free the memory of an allocated statvfs.
 *
 * @param  statvfs_o      The statvfs to free.
 */
SSH_API void sftp_statvfs_free(sftp_statvfs_t statvfs_o);

/**
 * @brief Canonicalize a sftp path.
 *
 * @param sftp          The sftp session handle.
 *
 * @param path          The path to be canonicalized.
 *
 * @return              The canonicalize path, NULL on error.
 */
SSH_API char *sftp_canonicalize_path(sftp_session_t *sftp, const char *path);

/**
 * @brief Get the version of the SFTP protocol supported by the server
 *
 * @param sftp          The sftp session handle.
 *
 * @return              The server version.
 */
SSH_API int sftp_server_version(sftp_session_t *sftp);

#ifdef WITH_SERVER
/**
 * @brief Create a new sftp server session.
 *
 * @param session       The ssh session to use.
 *
 * @param chan          The ssh channel to use.
 *
 * @return              A new sftp server session.
 */
SSH_API sftp_session_t *sftp_server_new(ssh_session_t * session, ssh_channel_t * chan);

/**
 * @brief Intialize the sftp server.
 *
 * @param sftp         The sftp session to init.
 *
 * @return             0 on success, < 0 on error.
 */
SSH_API int sftp_server_init(sftp_session_t *sftp);
#endif  /* WITH_SERVER */

/* this is not a public interface */
#define SFTP_HANDLES 256
sftp_packet_t * sftp_packet_read(sftp_session_t *sftp);
int sftp_packet_write(sftp_session_t *sftp,uint8_t type, ssh_buffer_t * payload);
void sftp_packet_free(sftp_packet_t * packet);
int buffer_add_attributes(ssh_buffer_t * buffer, sftp_attributes_t *attr);
sftp_attributes_t *sftp_parse_attr(sftp_session_t *session, ssh_buffer_t * buf,int expectname);
/* sftpserver.c */

SSH_API sftp_client_message_t * sftp_get_client_message(sftp_session_t *sftp);
SSH_API void sftp_client_message_free(sftp_client_message_t * msg);
SSH_API uint8_t sftp_client_message_get_type(sftp_client_message_t * msg);
SSH_API const char *sftp_client_message_get_filename(sftp_client_message_t * msg);
SSH_API void sftp_client_message_set_filename(sftp_client_message_t * msg, const char *newname);
SSH_API const char *sftp_client_message_get_data(sftp_client_message_t * msg);
SSH_API uint32_t sftp_client_message_get_flags(sftp_client_message_t * msg);
SSH_API int sftp_send_client_message(sftp_session_t *sftp, sftp_client_message_t * msg);
int sftp_reply_name(sftp_client_message_t * msg, const char *name,
    sftp_attributes_t *attr);
int sftp_reply_handle(sftp_client_message_t * msg, ssh_string_t * handle);
ssh_string_t * sftp_handle_alloc(sftp_session_t *sftp, void *info);
int sftp_reply_attr(sftp_client_message_t * msg, sftp_attributes_t *attr);
void *sftp_handle(sftp_session_t *sftp, ssh_string_t * handle);
int sftp_reply_status(sftp_client_message_t * msg, uint32_t status, const char *message);
int sftp_reply_names_add(sftp_client_message_t * msg, const char *file,
    const char *longname, sftp_attributes_t *attr);
int sftp_reply_names(sftp_client_message_t * msg);
int sftp_reply_data(sftp_client_message_t * msg, const void *data, int len);
void sftp_handle_remove(sftp_session_t *sftp, void *handle);

/* SFTP commands and constants */
#define SSH_FXP_INIT 1
#define SSH_FXP_VERSION 2
#define SSH_FXP_OPEN 3
#define SSH_FXP_CLOSE 4
#define SSH_FXP_READ 5
#define SSH_FXP_WRITE 6
#define SSH_FXP_LSTAT 7
#define SSH_FXP_FSTAT 8
#define SSH_FXP_SETSTAT 9
#define SSH_FXP_FSETSTAT 10
#define SSH_FXP_OPENDIR 11
#define SSH_FXP_READDIR 12
#define SSH_FXP_REMOVE 13
#define SSH_FXP_MKDIR 14
#define SSH_FXP_RMDIR 15
#define SSH_FXP_REALPATH 16
#define SSH_FXP_STAT 17
#define SSH_FXP_RENAME 18
#define SSH_FXP_READLINK 19
#define SSH_FXP_SYMLINK 20

#define SSH_FXP_STATUS 101
#define SSH_FXP_HANDLE 102
#define SSH_FXP_DATA 103
#define SSH_FXP_NAME 104
#define SSH_FXP_ATTRS 105

#define SSH_FXP_EXTENDED 200
#define SSH_FXP_EXTENDED_REPLY 201

/* attributes */
/* sftp draft is completely braindead : version 3 and 4 have different flags for same constants */
/* and even worst, version 4 has same flag for 2 different constants */
/* follow up : i won't develop any sftp4 compliant library before having a clarification */

#define SSH_FILEXFER_ATTR_SIZE 0x00000001
#define SSH_FILEXFER_ATTR_PERMISSIONS 0x00000004
#define SSH_FILEXFER_ATTR_ACCESSTIME 0x00000008
#define SSH_FILEXFER_ATTR_ACMODTIME  0x00000008
#define SSH_FILEXFER_ATTR_CREATETIME 0x00000010
#define SSH_FILEXFER_ATTR_MODIFYTIME 0x00000020
#define SSH_FILEXFER_ATTR_ACL 0x00000040
#define SSH_FILEXFER_ATTR_OWNERGROUP 0x00000080
#define SSH_FILEXFER_ATTR_SUBSECOND_TIMES 0x00000100
#define SSH_FILEXFER_ATTR_EXTENDED 0x80000000
#define SSH_FILEXFER_ATTR_UIDGID 0x00000002

/* types */
#define SSH_FILEXFER_TYPE_REGULAR 1
#define SSH_FILEXFER_TYPE_DIRECTORY 2
#define SSH_FILEXFER_TYPE_SYMLINK 3
#define SSH_FILEXFER_TYPE_SPECIAL 4
#define SSH_FILEXFER_TYPE_UNKNOWN 5

/**
 * @name Server responses
 *
 * @brief Responses returned by the sftp server.
 * @{
 */

/** No error */
#define SSH_FX_OK 0
/** End-of-file encountered */
#define SSH_FX_EOF 1
/** File doesn't exist */
#define SSH_FX_NO_SUCH_FILE 2
/** Permission denied */
#define SSH_FX_PERMISSION_DENIED 3
/** Generic failure */
#define SSH_FX_FAILURE 4
/** Garbage received from server */
#define SSH_FX_BAD_MESSAGE 5
/** No connection has been set up */
#define SSH_FX_NO_CONNECTION 6
/** There was a connection, but we lost it */
#define SSH_FX_CONNECTION_LOST 7
/** Operation not supported by the server */
#define SSH_FX_OP_UNSUPPORTED 8
/** Invalid file handle */
#define SSH_FX_INVALID_HANDLE 9
/** No such file or directory path exists */
#define SSH_FX_NO_SUCH_PATH 10
/** An attempt to create an already existing file or directory has been made */
#define SSH_FX_FILE_ALREADY_EXISTS 11
/** We are trying to write on a write-protected filesystem */
#define SSH_FX_WRITE_PROTECT 12
/** No media in remote drive */
#define SSH_FX_NO_MEDIA 13

/** @} */

/* file flags */
#define SSH_FXF_READ 0x01
#define SSH_FXF_WRITE 0x02
#define SSH_FXF_APPEND 0x04
#define SSH_FXF_CREAT 0x08
#define SSH_FXF_TRUNC 0x10
#define SSH_FXF_EXCL 0x20
#define SSH_FXF_TEXT 0x40

/* rename flags */
#define SSH_FXF_RENAME_OVERWRITE  0x00000001
#define SSH_FXF_RENAME_ATOMIC     0x00000002
#define SSH_FXF_RENAME_NATIVE     0x00000004

#define SFTP_OPEN SSH_FXP_OPEN
#define SFTP_CLOSE SSH_FXP_CLOSE
#define SFTP_READ SSH_FXP_READ
#define SFTP_WRITE SSH_FXP_WRITE
#define SFTP_LSTAT SSH_FXP_LSTAT
#define SFTP_FSTAT SSH_FXP_FSTAT
#define SFTP_SETSTAT SSH_FXP_SETSTAT
#define SFTP_FSETSTAT SSH_FXP_FSETSTAT
#define SFTP_OPENDIR SSH_FXP_OPENDIR
#define SFTP_READDIR SSH_FXP_READDIR
#define SFTP_REMOVE SSH_FXP_REMOVE
#define SFTP_MKDIR SSH_FXP_MKDIR
#define SFTP_RMDIR SSH_FXP_RMDIR
#define SFTP_REALPATH SSH_FXP_REALPATH
#define SFTP_STAT SSH_FXP_STAT
#define SFTP_RENAME SSH_FXP_RENAME
#define SFTP_READLINK SSH_FXP_READLINK
#define SFTP_SYMLINK SSH_FXP_SYMLINK

/* openssh flags */
#define SSH_FXE_STATVFS_ST_RDONLY 0x1 /* read-only */
#define SSH_FXE_STATVFS_ST_NOSUID 0x2 /* no setuid */


#ifdef _WIN32

//unsigned long long ntohll(unsigned long long val);

//unsigned long long htonll(unsigned long long val);
/** 64位网络字节需转换 */
#ifndef HTONLL_DEFINED
#define HTONLL_DEFINED
#define htonll(num) ((uint64_t)(htonl((uint32_t)(num))) << 32) + htonl((uint32_t)((num) >> 32))
#define ntohll(num) ((uint64_t)(ntohl((uint32_t)(num))) << 32) + ntohl((uint32_t)((num) >> 32))
#endif

#endif

#ifdef __cplusplus
} ;
#endif

#endif /* ! SSH_SFTP_H */

/** @} */
/* vim: set ts=2 sw=2 et cindent: */
