#define FUSE_USE_VERSION 30
#define _FILE_OFFSET_BITS 64
#define _DEFAULT_SOURCE // include daemon() 

#define APP_NAME "1541fs-fuse"
#ifndef VERSION
#define VERSION 0.1
#endif

#include <fuse3/fuse.h>
#include <fuse3/fuse_lowlevel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stddef.h>
#include <pthread.h>
#include <assert.h>
#include <syslog.h>
#include <signal.h>
#include <time.h>
#include <limits.h>
#include <opencbm.h>

extern int current_log_level;

#ifdef DEBUG_BUILD
#define PAD "        "
#else // DEBUG_BUILD
#define PAD ""
#endif // DEBUG_BUILD 
#define ERROR(format, ...) \
    if (current_log_level >= LOG_ERR) syslog(LOG_ERR, PAD format, ##__VA_ARGS__)
#define WARN(format, ...) \
    if (current_log_level >= LOG_WARNING) syslog(LOG_WARNING, PAD format, ##__VA_ARGS__)
#define INFO(format, ...) \
    if (current_log_level >= LOG_INFO) syslog(LOG_INFO, PAD format, ##__VA_ARGS__)
#ifdef DEBUG_BUILD
#define DEBUG(format, ...) \
    if (current_log_level >= LOG_DEBUG) syslog(LOG_DEBUG, PAD format, ##__VA_ARGS__)
#define ENTRY(...) \
    if (current_log_level >= LOG_DEBUG) \
        syslog(LOG_DEBUG, "ENTRY:  %s() %s, %d", __func__, __FILE__, __LINE__ ##__VA_ARGS__);
#define EXIT(...) \
    if (current_log_level >= LOG_DEBUG) \
        syslog(LOG_DEBUG, "EXIT:   %s() %s, %d", __func__, __FILE__, __LINE__,  ##__VA_ARGS__);
#define PARAMS(format, ...) DEBUG("PARAMS: %s() " format, __func__, ##__VA_ARGS__);
#else // DEBUG_BUILD
#define DEBUG(format, ...)
#define ENTRY(...)
#define EXIT(...)
#define PARAMS(format, ...)
#endif

// DELETE - replaced by cbmdummy.c
// What will be read out of format_disk
#define FORMAT_CONTENTS \
    "To format a disk write the new disk name followed by the ID to this file.\n" \
    "The disk name can be a maximum of 16 characters and the ID two digits.\n" \
    "Separate the two with a comma.  For example:\n" \
    "  echo \"my new disk,01\" > ./" PATH_FORMAT_DISK "\n"

// What will be read out of disk_reread
#define FORCE_DISK_REREAD_CONTENTS \
    "To force a disk re-read, write anything to this file.  For example:\n" \
    "  echo \"1\" > ./" PATH_FORCE_DISK_REREAD "\n"

// Various return string prefixes from Commdore DOS
#define DOS_OK_PREFIX "00"        // OK
#define DOS_BOOT_PREFIX "73,CBM"  // When drive has just powered up/reset
#define MAX_ERROR_LENGTH 48

// When allocating buffers for reading data, etc, allocate this much memory
// to being with, and if it's not enough use this as an increment to use to
// realloc.
#define BUF_INC 4096

// Commodore disk drive device numbers.
// Note that these are _device_ numbers, not _drive_ numbers.  Some Commodore
// disk units have 2 drives (the 2040, 3040, etc).  Those are a different
// concept, and not currently supported by this program.
#define DEFAULT_DEVICE_NUM 8
#define MIN_DEVICE_NUM     8
#define MAX_DEVICE_NUM     11

// Information about Commodore DOS channels.  There are 16 (0-15).
// 0, 1 and 15 are special:
// 0 - read
// 1 - write
// 15 - control channel (send commands, or receive status)
//2-14 inclusive can be used for other purposes.
#define NUM_CHANNELS      16
#define LOAD_CHANNEL     0
#define SAVE_CHANNEL      1
#define MIN_USER_CHANNEL  2
#define MAX_USER_CHANNEL  14
#define COMMAND_CHANNEL      15
#define DUMMY_CHANNEL     16  // Used to access dummy files/directories
#define MIN_CHANNEL       0
#define MAX_CHANNEL       DUMMY_CHANNEL

// Other information about Commodore disk file sytem and d
#define CBM_BLOCK_SIZE 256
#define MAX_CBM_FILENAME_STR_LEN 16+1 // 16 chars, plus 1 for NULL terminator
#define MAX_FUSE_FILENAME_STR_LEN MAX_CBM_FILENAME_STR_LEN+1+3 // 1 for period, 3 for suffix
#define CBM_ID_STR_LEN       2+1      // 2 chars, plus 1 for NULL terminator
#define CBM_FILE_TYPE_LEN 3
#define CBM_FILE_TYPE_STR_LEN CBM_FILE_TYPE_LEN+1  // 3 chars, 1 terminator
#define MAX_HEADER_LEN   16+1+2+1 // 16 chars + 1 for comma + 2 for ID + 1 null terminator
#define MAX_FILE_LEN     16
#define CBM_ID_LEN       2

#define DELIM_FILE  '.'
#define DELIM_HDR   ','

#define DUMMY_FILE_SUFFIX "cmd"

// We allocate the files array in cbm_state in blocks of tihs quantity
#define CBM_FILE_REALLOCATE_QUANTITY  10

// Valid uses for disk drive channels 
enum cbm_channel_usage
{
    // Unused
    USAGE_NONE,

    // Reserved for channel 0
    USAGE_LOAD,

    // Reserved for channel 1
    USAGE_SAVE,

    // Used by channel 15
    USAGE_COMMAND,

    // Used by other channels (specifically as requested by FUSE)
    USAGE_OPEN,
};

// Information about a specific channel to the device, including whether it's
// open and what for.
struct cbm_channel
{
    // Can be between 0 and NUM_CHANNELS-1
    int num;

    // Whether this channel has been opened (and not closed)
    int open;

    // What this channel is being used for (may be retired if unnecessary)
    enum cbm_channel_usage usage;

    // If usage is USAGE_OPEN (channels 2-14) and open is 1, stores the file
    // entry
    struct cbm_file *file;

    // Opaque handles stored on behalf of code handling open/release/read/write
    // operations.  May be used, for example, to store the entirety of a file
    // read in in one go, so that subsequent read calls (before a release)
    // don't require re-reading the file 
    void *handle1;
    int handle2;
};

enum cbm_file_type
{
    // Used for entry cbm_file entries
    CBM_NONE,

    // A Commodore PRG file
    CBM_PRG,

    // A Commodore SEQ file
    CBM_SEQ,

    // A Commodore USR file
    CBM_USR,

    // A Commodore REL file
    CBM_REL,

    // A Commodore disk header 
    CBM_DISK_HDR,

    // A dummy directory, which doesn't exist on the disk - such as . and ..
    CBM_DUMMY_DIR,

    // A file which is exposed on only the FUSE FS to provide some type of
    // control
    CBM_DUMMY_FILE,
};

// Supported suffix which map to file types
#define NUM_CBM_FILE_TYPES  4
#define SUFFIX_PRG  "PRG"
#define SUFFIX_SEQ  "SEQ"
#define SUFFIX_REL  "REL"
#define SUFFIX_USR  "USR"
#define SUFFIX_PRG_LOWER  "prg"
#define SUFFIX_SEQ_LOWER  "seq"
#define SUFFIX_REL_LOWER  "rel"
#define SUFFIX_USR_LOWER  "usr"

// Used by create_file_entry() in cbmfile.c
enum file_source
{
    SOURCE_CBM,   // A file which exists on the physical media
    SOURCE_DUMMY, // 1541fs dummy file (not to be created on media)
    SOURCE_FUSE,  // FUSE created file (to be created on media)
};

// Callbacks when FUSE requests operation on a cbm_file entry
struct cbm_state;
struct cbm_file;
typedef int (*callback_open) (struct cbm_state *cbm,
                              int handle,
                              struct cbm_file *entry,
                              const char *path,
                              struct fuse_file_info *fi);
typedef int (*callback_release) (struct cbm_state *cbm,
                                 int handle,
                                 struct cbm_file *entry,
                                 const char *path,
                                 struct fuse_file_info *fi);
typedef int (*callback_read) (struct cbm_state *cbm,
                              int handle,
                              struct cbm_file *entry,
                              const char *path,
                              char *buf,
                              size_t size,
                              off_t offset,
                              struct fuse_file_info *fi);
typedef int (*callback_write) (struct cbm_state *cbm,
                               int handle,
                               struct cbm_file *entry,
                               const char *path,
                               const char *buf,
                               size_t size,
                               off_t offset,
                               struct fuse_file_info *fi);
struct callbacks
{
    int handle;
    callback_open open;
    callback_release release;
    callback_read read;
    callback_write write;
};

// Information about a file.  This might be a file which actually exists on
// the disk, one which has been created by the kernel but not yet written to
// the disk, or a dummy one we will expose in the FUSE FS, but doesn't
// actually exist on the disk
struct cbm_file
{
    // The type of file
    enum cbm_file_type type;

    // The filename on the Commodore disk
    // A zero length string for types CBM_DUMMY_DIR and CBM_DUMMY_FILE
    // Stored as PETSCII
    char cbm_filename[MAX_CBM_FILENAME_STR_LEN];

    // The ID of the disk header.  Only valid where type is CBM_DISK_HDR
    char cbm_header_id[CBM_ID_STR_LEN];

    // The name of this file on the FUSE FS
    // Stored as ASCII 
    char fuse_filename[MAX_FUSE_FILENAME_STR_LEN];

    // Linux file properties (size, timestamps, permissions, etc) 
    struct stat st;

    // Number of Commodore disk (256 byte) blocks this file uses
    // Zero for CBM_DUMMY_DIR and CBM_DUMMY_FILE types
    off_t cbm_blocks;

    // Size in bytes of the file.
    // For a CBM file this is 0 until the file has been completely read
    // as we only know blocks until then.
    // We set to 0 for CBM_DUMMY_DIR and CBM_DUMMY_FILE types (unless we
    // decide to expose a different value)
    off_t filesize;

    // For CBM_PRG, CBM, USR, CBM_REL, CBM_SEQ indicates whether the file is
    // not yet actually written to the disk - happens after an open but before
    // a write
    int not_yet_on_disk;

    // Pointer to channel for this file.
    // Only non-NULL if file is open
    struct cbm_channel *channel;

    // Callbacks.  If NULL that function (read/write) will not be supported
    // for this file
    struct callbacks cbs;
};

// Our FUSE private data.  When called by FUSE, this can be retrieved via
// fuse_get_context()->private_data. 
typedef struct cbm_state
{
    // FUSE's private data, which we have to provide on every call to FUSE.
    // However, we only access this from with the signal handler - within 
    // a FUSE callback context we access via fuse_get_context()->private_data.
    struct fuse *fuse;

    // FUSE's file handle for this mount.  We don't use this after receiving
    // it in response to mounting (unmounting doesn't require it).
    int fuse_fh;

    // Boolean indicating whether we've called fuse_loop yet.
    int fuse_loop;

    // Boolean indicating whether fuse_exit() has been called.
    int fuse_exited;

    // Path to mount CBM FUSE FS
    char *mountpoint;

    // Whether to daemonize after initialization
    int daemonize;

    // Whether is now running as a daemon
    int is_daemon;

    // Boolean indicating whether to force a bus (IEC/IEEE-488) reset before
    // attempting to mount
    int force_bus_reset;

    // Boolean indicating whether to ignore format requests via the special
    // file
    int dummy_formats; 

    // Protect access to this data with a mutex.  This mutex will not be used/
    // honoured by the signal handler, if called, nor by the main cleanup code.
    // In the former case because the signal handler could be called when the 
    // mutex is held, and in the latter case because all fuse processing should
    // have exited before the cleanup code is called.  In both cases we want to
    // avoid blocking due to the mutex lock being held elsewhere. 
    pthread_mutex_t mutex;
    int mutex_initialized;

    // The file descriptor from opencbm, used for all XUM1541 access
    CBM_FILE fd;

    // Commodore device number for this mount - may be 8, 9, 10 or 11
    unsigned char device_num;

    // Boolean indicating whether we have opened the OpenCBM driver
    //successfully.
    int is_initialized;

    // Used to store the last error string the drive.  Examples:
    // 00,OK,00,00
    // 73,CBM DOS 1541 v2.6,00,00
    // etc.  Note may or may not be spaces after commas.
    char error_buffer[MAX_ERROR_LENGTH];

    // Whether we succeeded in doing a successfully read of the floppy disk's
    // directory last time around - and hence whether the data in dir_entries
    // is valid.  Can be used to avoid requerying the physical media if we
    // don't think anything else has changed.
    int dir_is_clean;

    // Array containing information about all potentially used channels.
    // Users only need store information about the channels in use if they
    // will remain unused beyond a mutex lock.  If only used within a mutex 
    // and they were free before and will remaing free after, they can be used
    // without updating channels.
    // However, where channels remaing in use between mutex calls - for
    // example when instructed to open a channel by FUSE, and then subsequently
    // read, they must be reserved here. 
    struct cbm_channel channel[NUM_CHANNELS];

    // Pointer to array of file structs, which store information about all
    // files, including all those on the physical disk, plus those "invented"
    // by this FUSE FS.
    //
    // This array is reallocated as necessary, although we allocate in blocks
    // so reallocation isn't necessary every time a file is created or
    // destroyed.  (CBM_FILE_REALLOCATE_QUANTITY is used to decide in what
    // size chunks we allocate or deallocate.
    //
    // Elements in this array are used contiguously, starting from 0, so any
    // unused ones are at the end.
    struct cbm_file *files;

    // Number of files that are present in the files field (i.e. number of
    // elements in the files array which are used).
    size_t num_files;

    // The size of the files array - i.e. the number of elements which the
    // array will currently hold.  If more are required then files will need
    // to be reallocated.  (We will also reallocate if substantially fewer
    // are required.)
    size_t max_num_files;
} CBM;

// Used to store information about dummy files - their names and the (read)
// contents
struct dummy_files
{
    const char *filename;
    const char *read_contents;
};

// cbmargs.c
extern int process_args(struct fuse_args *args, CBM *cbm);
extern void destroy_args(CBM *cbm);

// cbmchannel.c
extern int allocate_free_channel(CBM *cbm,
                                 enum cbm_channel_usage usage,
                                 struct cbm_file *entry);
extern void release_channel(CBM *cbm, int ch);

// cbmdisk.c
extern int process_format_request(CBM *cbm, const char *buf, size_t size);
extern struct callbacks disk_cbs;

// cbmdummy.c
extern int create_dummy_entries(CBM *cbm);

// cbmfile.c
extern int read_dir_from_disk(CBM *cbm);
extern void destroy_files(CBM *cbm);
extern struct cbm_file *return_next_free_file_entry(CBM *cbm);
extern void update_fuse_stat(struct cbm_file *entry);
extern void free_file_entry(CBM *cbm, struct cbm_file *file);
extern struct cbm_file *find_file_entry(CBM *cbm,
                                        const char *cbm_filename,
                                        const char *fuse_filename);
extern struct cbm_file *find_cbm_file_entry(CBM *cbm,
                                            const char *filename);
extern struct cbm_file *find_fuse_file_entry(CBM *cbm,
                                             const char *filename);
extern struct cbm_file *create_file_entry(CBM *cbm,
                                          const enum file_source source,
                                          const char *filename,
                                          const char *suffix,
                                          const int directory,
                                          const off_t size,
                                          struct callbacks *cbs,
                                          int *error);
extern struct cbm_file *create_cbm_file_entry(CBM *cbm,
                                              const char *filename,
                                              const char *suffix,
                                              const off_t cbm_blocks,
                                              struct callbacks *cbs,
                                              int *error);
extern struct cbm_file *create_fuse_file_entry(CBM *cbm,
                                               const char *filename,
                                               const off_t filesize,
                                               struct callbacks *cbs,
                                               int *error);
extern struct cbm_file *create_dummy_file_entry(CBM *cbm,
                                                const char *filename,
                                                const int directory,
                                                const off_t filesize,
                                                struct callbacks *cbs,
                                                int *error);
extern void remove_file_entries_source(CBM *cbm, enum file_source source);
extern int is_dummy_file(struct cbm_file *entry);
#ifdef DEBUG_BUILD
extern void log_file_entries(CBM *cbm);
#endif // DEBUG_BUILD

// cbmfuse.c
extern int cbm_pre_init(CBM *cbm);
extern void cbm_destroy(void *private_data);
extern const struct fuse_operations cbm_operations;

// cbmlog.c
extern void init_logging();

// cbmmain.c
extern void destroy_private_data(CBM *cbm, int clean);
int kill_fuse_thread(void);

// cbmsignal.c
extern int setup_signal_handler(CBM *cbm);
extern void cleanup_signal_handler();

// cbmstatus.c
extern int check_drive_status_cmd(CBM *cbm, char *cmd);
extern int check_drive_status(CBM *cbm);

// cbmthread.c
extern void cbm_create_read_dir_thread(CBM *cbm);
