#define FUSE_USE_VERSION 30
#define _FILE_OFFSET_BITS 64

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
#include <opencbm.h>

extern int current_log_level;

#define ERROR(format, ...) \
    if (current_log_level >= LOG_ERR) syslog(LOG_ERR, format, ##__VA_ARGS__)
#define WARN(format, ...) \
    if (current_log_level >= LOG_WARNING) syslog(LOG_WARNING, format, ##__VA_ARGS__)
#define INFO(format, ...) \
    if (current_log_level >= LOG_INFO) syslog(LOG_INFO, format, ##__VA_ARGS__)
#ifdef DEBUG_BUILD
#define DEBUG(format, ...) \
    if (current_log_level >= LOG_DEBUG) syslog(LOG_DEBUG, format, ##__VA_ARGS__)
#else // DEBUG_BUILD
#define DEBUG(format, ...)
#endif

// What will be read out of format-disk
#define FORMAT_CONTENTS \
    "To format a disk write the new disk name followed by the ID to this file.\n" \
    "The disk name can be a maximum of 16 characters and the ID two digits.\n" \
    "Separate the two with a comma.  For example:\n" \
    "my new disk,01"


// Various return string prefixes from Commdore DOS
#define DOS_OK_PREFIX "00"        // OK
#define DOS_BOOT_PREFIX "73,CBM"  // When drive has just powered up/reset
#define MAX_ERROR_LENGTH 48

// When allocating buffers for reading data, etc, allocate this much memory
// to being with, and if it's not enough use this as an increment to use to
// realloc.
#define BUF_INC 1024

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
#define MIN_USER_CHANNEL  2
#define MAX_USER_CHANNEL  14
#define DUMMY_CHANNEL     16  // Used to access dummy files/directories

// Other information about Commodore disk file sytem and d
#define CBM_BLOCK_SIZE 256
#define MAX_CBM_FILENAME_STR_LEN 16+1 // 16 chars, plus 1 for NULL terminator
#define MAX_FUSE_FILENAME_STR_LEN MAX_CBM_FILENAME_STR_LEN+1+3 // 1 for period, 3 for suffix
#define CBM_ID_STR_LEN       2+1      // 2 chars, plus 1 for NULL terminator
#define CBM_FILE_TYPE_STR_LEN 3+1  // 3 chars, 1 terminator
#define MAX_FILENAME_LEN 16+1+3+1 // 16 chars + 1 for period + 3 for file ending + 1 null terminator
#define MAX_HEADER_LEN   16+1+2+1 // 16 chars + 1 for comma + 2 for ID + 1 null terminator
#define MAX_FILE_LEN     16
#define ID_LEN           2
#define DUMMY_FILE_SUFFIX_LEN 3+1

#define DELIM_FILE  "."
#define DELIM_HDR   ","

#define DUMMY_FILE_SUFFIX "cmd"

// We allocate the files array in cbm_state in blocks of tihs quantity
#define CBM_FILE_REALLOCATE_QUANTITY  10

// Special paths - declared in cmbfile.c
extern const char *special_dirs[];

// Special files - declared in cbmfiles.c
#define PATH_FORCE_DISK_REREAD  "disk_reread.cmd" // Could use header for this
#define PATH_FORMAT_DISK        "format_disk.cmd"       // Could also use header for this
extern const char *special_files[];

// Valid uses for disk drive channels 
enum cbm_channel_usage
{
    // Unused
    USAGE_NONE,

    // Reserved for channel 0
    USAGE_READ,

    // Reserved for channel 1
    USAGE_WRITE,

    // Used by channel 15
    USAGE_CONTROL,

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
    // of the filename opened
    char filename[MAX_FILENAME_LEN];
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

// Used by create_file_entry() in cbmfile.c
enum file_source
{
    SOURCE_CBM,
    SOURCE_LINUX,
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
    char *cbm_filename[MAX_CBM_FILENAME_STR_LEN];

    // The ID of the disk header.  Only valid where type is CBM_DISK_HDR
    char *cbm_header_id[CBM_ID_STR_LEN];

    // The name of this file on the FUSE FS
    // Stored as ASCII 
    char *fuse_filename[MAX_FUSE_FILENAME_STR_LEN];

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
};

// Information about an entry from the disk directory.  May be either a header
// (disk name,ID), or a file (name.suffix).
struct cbm_dir_entry
{
    // Number of blocks on the disk used by this file.  Note that Commodore
    // disk blocks are 256 bytes, whereas FUSE expects to be provided the
    // number of 512 byte blocks, so we need to convert.
    unsigned short num_blocks;

    // Filesize in bytes.  Technically this isn't correct as it's calculated
    // by multiplying the number of blocks by 256.  But we wouldn't know the
    // correct value without reading the entire file, which we won't do.  This
    // may lead to some unexpected behaviour, if this filesize is relied upon
    // when listing then processing files.
    unsigned int filesize;

    // Filename.  We use the convention of stripping and trailing spaces
    // from the filename from disk, the appending a suffix, preceeeded by a
    // period, indicating the Commodore file type - so .prg .usr .seq .rel
    // etc.  If the file stored is called test and a PRG file, it'll be
    // stored and shown as test.prg.  Note that if a file test.prg is stored
    // as a prg, it will be called test.prg.prg.  Any spaces within the
    // filename including at the beginning will be retained.
    char filename[MAX_FILENAME_LEN];

    // indicates whether should be treated as a directory.
    // In terms of entries read from disk only the header is a directory.
    // However, we also use this struct for special_dirs (and files).
    unsigned char is_dir;

    // Indicates whether this is a file representing the header of
    // the disk (i.e. the disk name and ID).  These are separated using a
    // comma, rather than a period, which is a common Commodore convention.
    // E.g. "scratch disk,01" without the quotes.
    unsigned char is_header;

    // Indicates wther this is a special file (made up and exposed by 1541fs
    // in order to provide additional information or functionality
    unsigned char is_special;
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

    // Number of valid entries in dir_entries - so number of files in the
    // directory.  This includes any "special" files, like the disk header
    // which we represent as a file, but not . or .., which are faked by
    // the _readdir() function, and not stored in dir_entries.  Note there
    // may be more memory pointed to by dir_entries than num_dir_entries
    // suggests.  That's OK as if/when we free the OS will take care of
    // freeing it all.  However we may unnecessary realloc dir_entries if
    // we subsequently need more (and there was more hiding there than we
    // expected).  If you want to understand why this is the case read the
    // code in read_dir_from_disk - but it's essentially because:
    // * we estimate how many entries there will be before we know and
    //   allocate memory based on that (which may be an over-estimate)
    // * and if we subsequently do a directory read and there are fewer files
    //   we will avoid a reallocation at that point - but num_dir_entries will
    //   always represent the valid number of dir_entries, not the amount of
    //   space for them (but there will always be enough space for the number
    //   specified, or we will re-alloc.
    int num_dir_entries;

    // Actual directory entires, including special files, excepting . and ..
    struct cbm_dir_entry *dir_entries;

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

// cbmargs.c
extern int process_args(struct fuse_args *args, CBM *cbm);
extern void destroy_args(CBM *cbm);

// cbmchannel.c
extern int allocate_free_channel(CBM *cbm,
                                 enum cbm_channel_usage usage,
                                 const char *filename);
extern void release_channel(CBM *cbm, int ch);

// cbmfile.c
extern int read_dir_from_disk(CBM *cbm);
extern int is_special_dir(const char *path);
extern int is_special_file(const char *path);
extern void set_stat(struct cbm_dir_entry *entry, struct stat *stbuf);
extern void destroy_files(CBM *cbm);
extern struct cbm_file *return_next_free_file_entry(CBM *cbm);
extern void free_file_entry(CBM *cbm, struct cbm_file *file);
extern struct cbm_file *find_file_entry(CBM *cbm,
                                        char *cbm_filename,
                                        char *fuse_filename);
extern struct cbm_file *create_file_entry(CBM *cbm,
                                          const enum file_source source,
                                          const char *filename,
                                          const char *suffix,
                                          const int directory,
                                          const off_t size,
                                          int *errno);
#define create_file_entry_cbm(CBM, FILENAME, SUFFIX, CBM_BLKS, ERRNO) \
        create_file_entry(CBM,        \
                          FILENAME,   \
                          SUFFIX,     \
                          SOURCE_CBM, \
                          0,          \
                          CBM_BLKS,   \
                          ERRNO)
#define create_file_entry_dummy(CBM, FILENAME, SUFFIX, ISDIR, FILESIZE, ERRNO) \
        create_file_entry(CBM,        \
                          FILENAME,   \
                          SUFFIX,     \
                          SOURCE_CBM, \
                          ISDIR,      \
                          FILESIZE,   \
                          ERRNO)

// cbmfuse.c
extern void cbm_destroy(void *private_data);
extern const struct fuse_operations cbm_operations;

// cbmlog.c
extern void init_logging();

// cbmmain.c
extern void destroy_private_data(CBM *cbm, int clean);

// cbmsignal.c
extern void setup_signal_handler(CBM *cbm);
extern void cleanup_signal_handler();

// cbmstatus.c
extern int check_drive_status_cmd(CBM *cbm, char *cmd);
extern int check_drive_status(CBM *cbm);

// cbmthread.c
extern void cbm_create_read_dir_thread(CBM *cbm);
