#include "cbmfuse.h"

// KEEP - rename?
// Special paths
// Must not begin or terminate the / or FUSE will barf
const char *special_dirs[] =
{
    ".",
    "..",
    NULL
};

// KEEP - rename?
const char *special_files[] = {
    PATH_FORCE_DISK_REREAD,
    PATH_FORMAT_DISK,
    NULL,
};

// KEEP
// Removes any trailing spaces from the end of a string
// Returns the new string length
static int remove_trailing_spaces(char *str) {
    int len = (int)strlen(str);
    int ii;

    // Iterate from the end of the string towards the beginning
    for (ii = len - 1; ii >= 0; ii--)
    {
        if (str[ii] != ' ')
        {
            break;
        }
    }

    // Terminate the string after the last non-space character
    str[ii + 1] = '\0';

    return (ii + 1);
}

// DELETE
// Reallocates a line_count number of directory entries, retaining the
// existing entries
static void realloc_dir_entries(CBM *cbm, int line_count)
{
    if (line_count > cbm->num_dir_entries)
    {
        // We can't reuse - better free and malloc a new one
        if (cbm->dir_entries != NULL)
        {
            free(cbm->dir_entries);
            cbm->dir_entries = NULL;
        }
        cbm->dir_entries = malloc((size_t)line_count * sizeof(struct cbm_dir_entry));
        if (cbm->dir_entries != NULL)
        {
            cbm->num_dir_entries = line_count;
        }
        else
        {
            cbm->num_dir_entries = 0;
            goto EXIT;
        }
    }
    memset(cbm->dir_entries, 0, (size_t)line_count * sizeof(struct cbm_dir_entry));

EXIT:

    return;
}

// KEEP
// Reallocates a buffer if we've run out of space
static void check_realloc_buffer(char **buffer,
                          unsigned int *buf_len,
                          const unsigned int pos)
{
    char *new_buffer;

    assert(buffer != NULL);
    if (pos >= *buf_len)
    {
        *buf_len += BUF_INC;
        new_buffer = realloc(*buffer, *buf_len);

        // The following handles the case if the remalloc failed -
        // the original buffer will still be freed, and buffer set to NULL
        if (new_buffer == NULL)
        {
            // Realloc frees buffer if it moves it
            free(*buffer);
        }
        *buffer = new_buffer;
    }
}

// REWORK (what a nightmare!)
// Reads in the directory from a CBM disk
int read_dir_from_disk(CBM *cbm)
{
    unsigned int buf_len;
    unsigned int data_len;
    unsigned int pos;
    char *buffer = NULL;
    int rc = 0;
    int error;
    char c;
    int line_count;
    struct cbm_dir_entry *dir_entry = NULL;

    cbm->dir_is_clean = 0;

    // malloc a buffer to store data read from the disk in
    DEBUG("Allocate buffer to read in data");
    buf_len = BUF_INC;
    buffer = malloc(buf_len);
    if (buffer == NULL)
    {
        DEBUG("Failed to allocate memory for buffer to read dir into");
        rc = -ENOMEM;
        goto EXIT;
    }

    // open the directory "file" ($)
    DEBUG("Open $");
    c = cbm_ascii2petscii_c('$');
    error = cbm_open(cbm->fd, cbm->device_num, 0, &c, 1);
    if (error)
    {
        DEBUG("Open of $ failed");
        rc = -EIO;
        goto EXIT;
    }
    cbm_talk(cbm->fd, cbm->device_num, 0);

    // Read in directory listing from the drive
    DEBUG("Read in directory data");
    pos = 0;
    while (cbm_raw_read(cbm->fd, buffer + pos, 1) == 1)
    {
        pos++;
        if (pos >= buf_len)
        {
            check_realloc_buffer(&buffer, &buf_len, pos);

        }
        if (buffer == NULL)
        {
            DEBUG("Out of memory while reading directory");
            rc = -ENOMEM;
            goto EXIT;
        }
    }
    data_len = pos;
    DEBUG("Read %d bytes total directory listing", data_len);

    cbm_untalk(cbm->fd);
    if (check_drive_status(cbm))
    {
        DEBUG("Hit error reading from disk");
        goto EXIT;
    }
    cbm_close(cbm->fd, cbm->device_num, 0);

    // Estimate how many lines there are - we'll estimate 28 bytes to a line
#define APPROX_BYTES_IN_DIR_LINE 28
    DEBUG("Calculate appox number of lines in directory listing");
    int approx_line_count = (int)(data_len / APPROX_BYTES_IN_DIR_LINE + (data_len % APPROX_BYTES_IN_DIR_LINE ? 1 : 0));
    DEBUG("Approximate number of lines in directory listing: %d", approx_line_count);
    if (approx_line_count <= 0)
    {
        DEBUG("0 lines in directory listing");
        goto EXIT;
    }

    DEBUG("Realloc directory entries");
    realloc_dir_entries(cbm, approx_line_count);
    if (cbm->dir_entries == NULL)
    {
        DEBUG("Failed to allocate memory for directory entries");
        rc = -ENOMEM;
        goto EXIT;
    }

    // Note our number of directory entries may be wrong - we'll figure this out
    // later

    // Check 1st 3 bytes
    DEBUG("Check 1st 4 bytes of listing");
    pos = 0;
    if (data_len < 4)
    {
        DEBUG("Fewer than 4 bytes in whole dir listing");
        goto EXIT;
    }
    if ((buffer[0] != 0x1) ||
        (buffer[1] != 0x4) ||
        (buffer[2] != 0x1) ||
        buffer[3] != 0x1)
    {
        DEBUG("Unexpected first 4 bytes: 0x%x 0x%x 0x%x 0x%x",
              buffer[0],
              buffer[1],
              buffer[2],
              buffer[3]);
        goto EXIT;
    }
    pos += 4;

    // Now read lines
    DEBUG("Read lines of listing");
    dir_entry = cbm->dir_entries;
    assert(dir_entry != NULL);
    line_count = 0;
    while (pos < data_len)
    {
        DEBUG("Reading line of listing");

        // Check if have run out of dir_entries
        if (cbm->num_dir_entries < (line_count+1))
        {
            INFO("Estimated number of lines in directory incorrectly");
            realloc_dir_entries(cbm, line_count+1);
            if (cbm->dir_entries == NULL)
            {
                DEBUG("Failed to reallocate memory for directory entries");
                rc = -ENOMEM;
                goto EXIT;
            }
        }
        
        DEBUG("Get blocks for this file");
        // Get the number of blocks for this file
        if (pos >= (buf_len + 2))
        {
            DEBUG("Ran out of data too soon");
            goto EXIT;
        }
        DEBUG("Next 2 bytes for block size: 0x%x 0x%x", (unsigned char)buffer[pos], (unsigned char)buffer[pos+1]);
        dir_entry->num_blocks = (unsigned char)buffer[pos++];
        // If the 2nd byte is 0x12 that means reverse text - so header
        // Assume any value below this is high order byte, any value
        // above this isn't.
        if (buffer[pos] < 0x12)
        {
            dir_entry->num_blocks |= (unsigned short)(buffer[pos++] << 8);
        }
        dir_entry->filesize = dir_entry->num_blocks * CBM_BLOCK_SIZE;
        DEBUG("Num blocks: %d, Filesize: %d", dir_entry->num_blocks, dir_entry->filesize);

        int filename_started = 0;
        int filename_ended = 0;
        int filename_len = 0;
        int is_header = 0;
        int is_footer = 0;
        int suffix_ended = 0;
        char suffix[4] = {0, 0, 0, 0};
        int suffix_len = 0;

        DEBUG("Read rest of line data");
        while ((pos < data_len) && 
               (buffer[pos] != 0x1))
        {
            c = buffer[pos];
            DEBUG("Got byte: 0x%x", c);
            if (is_footer)
            {
                // ignore the footer - just says "blocks free"
                DEBUG("Footer - ignore");
                assert(!filename_started);
            }
            else if (suffix_ended)
            {
                // ignore any remaining bytes
            }
            else if (!filename_started)
            {
                assert(!filename_ended);
                if (c == 0x20)
                {
                    // ignore leading spaces
                }
                else if (c == 0x12)
                {
                    DEBUG("Found header");
                    is_header = 1;
                    dir_entry->is_header = 1;
                }
                else if (c == '"')
                {
                    DEBUG("Filename started");
                    filename_started = 1;
                }
                else if (c == 0x42) // PETSCII for b
                {
                    DEBUG("Found footer");
                    assert(!is_header);
                    is_footer = 1;
                }
            }
            else if (!filename_ended)
            {
                assert(!is_footer);
                if (c == '"')
                {
                    DEBUG("Filename ended");
                    filename_ended = 1;
                }
                else
                {
                    DEBUG("Add char to filename: %c", c);
                    // Any other char just gets added to the filename
                    // We'll cope with trailing spaces when appending the .XXX
                    // suffix
                    // We sade 5 chars for the 4 digit suffix and 1xNULL terminator
                    if (filename_len < (MAX_FILENAME_LEN - 5))
                    {
                        dir_entry->filename[filename_len] = cbm_petscii2ascii_c(c);
                        filename_len++;
                    }
                    else
                    {
                        WARN("Filename is longer than max len - truncated version is: %s", dir_entry->filename);
                    }
                }
            }
            else if (suffix_len > 0)
            {
                if (c == ' ')
                {
                    DEBUG("End of suffix: %s", suffix);
                    // Suffix has ended - we could match with valid ones, but
                    // we won't bother - instead we'll just add to the
                    // filename
                    filename_len = remove_trailing_spaces(dir_entry->filename);
                    assert(filename_len < (MAX_FILENAME_LEN - 5));
                    dir_entry->filename[filename_len] = dir_entry->is_header ? ',' : '.';
                    dir_entry->filename[filename_len+1] = 0;
                    strncat(dir_entry->filename, suffix, 4);
                    suffix_ended = 1;
                }
                else if (suffix_len < 3)
                {
                    DEBUG("Add char to suffix: %c", c);
                    suffix[suffix_len++] = cbm_petscii2ascii_c(c);
                }
                else
                {
                    // Drop any more chars
                    assert(suffix[3] == 0);
                    WARN("Suffix is too long - truncated version is: %s", suffix);
                }
            }
            else
            {
                assert(filename_started);
                assert(filename_ended);
                assert(!is_footer);
                assert(suffix_len == 0);
                if (c == ' ')
                {
                    DEBUG("Ignore space after filename and before suffix");
                    // Ignore
                }
                else
                {
                    DEBUG("First char of suffix: %c", c);
                    suffix[suffix_len++] = cbm_petscii2ascii_c(c);
                }
            }

            // Move to next char
            pos++;
        }


        if (!is_footer)
        {
            DEBUG("Added directory entry #%d: header %d name %s size %d cbm blocks %d",
                line_count,
                dir_entry->is_header,
                dir_entry->filename,
                dir_entry->filesize,
                dir_entry->num_blocks);
            dir_entry++;
            line_count++;
        }

        // Don't add the footer
        if (pos >= (buf_len + 2))
        {
            DEBUG("Not enough data to read another line - exiting line parsing");
        }
        // Next two bytes should be 0x1 and 0x1, or 0x0 and 0x0 after footer
        DEBUG("Skipping next 2 bytes: 0x%d 0x%d", buffer[pos], buffer[pos+1]);
        pos += 2;
    }

    assert(line_count <= cbm->num_dir_entries);
    cbm->num_dir_entries = line_count;
    cbm->dir_is_clean = 1;
    rc = 0;

EXIT:

    DEBUG("Exiting read directory function");
    if (!rc)
    {
        DEBUG("Number of directory entries: %d is_clean: %d", cbm->num_dir_entries, cbm->dir_is_clean);
    }

    if (buffer != NULL)
    {
        free(buffer);
    }

    return rc;

}

// DELETE
// Generic function which decides in this is a special file or special
// directory
static int is_special(const char *path, const char **strings)
{
    int ii;
    const char *match;
    int rc = 0;
    if (!strcmp(path, "/"))
    {
        rc = 1;
        goto EXIT;
    }
    for (ii = 0, match=strings[ii];
         match != NULL;
         ii++, match=strings[ii])
    {
        if (!strcmp(path+1, match))
        {
            rc = 1;
            goto EXIT;
        }
    }

EXIT:

    return rc;
}

// DELETE
int is_special_dir(const char *path)
{
    return is_special(path, special_dirs);
}

// DELETE
int is_special_file(const char *path)
{
    return is_special(path, special_files);
}

// DELETE
// Sets up stat information about the file in order to provide it to FUSE
void set_stat(struct cbm_dir_entry *entry, struct stat *stbuf)
{
    memset(stbuf, 0, sizeof(*stbuf));

    // Num blocks is tricky.  It's supposed to represent the number of
    // 512 byte blocks.  But our filesystem has size 256 blocks.  So we
    // must convert into 512 byte blocks
    assert(CBM_BLOCK_SIZE == 256);
    stbuf->st_blocks = (int)((entry->filesize + 255) / 256 / 2);
    stbuf->st_blksize = CBM_BLOCK_SIZE;
    stbuf->st_size = (int)(entry->filesize);
    if (!entry->is_dir)
    {
        stbuf->st_mode |= S_IFREG | 0444;
        stbuf->st_nlink = 1;
    }
    else
    {
        stbuf->st_mode |= S_IFDIR | 0555;
        stbuf->st_nlink = 2;
    }
    if (!entry->is_special)
    {
        stbuf->st_atime = stbuf->st_ctime = stbuf->st_mtime = time(NULL);
    }
}

// Above here needs to be significantly reworked

// Frees up any memory associated with file entrys in cbm_state.
void destroy_files(CBM *cbm)
{
    DEBUG("ENTRY: destroy_files()");

    if (cbm->dir_entries != NULL)
    {
        free(cbm->dir_entries);
        cbm->dir_entries = NULL;
    }
    if (cbm->files != NULL)
    {
        free(cbm->files);
        cbm->files = NULL;
    }

    DEBUG("EXIT: destroy_files()");
}

// Fills in the fuse_filename field in a cbm_file struct, assuming that the
// cbm_filename, header_id (if type == CBM_DISK_HDR) and type fields are set.
static void update_fuse_filename_from_cbm(struct cbm_file *entry)
{
    char *suffix;
    char *delim = DELIM_FILE;

    DEBUG("ENTRY: update_fuse_filename_from_cbm()");

    assert(entry != NULL);
    assert((entry->type == CBM_PRG) ||
           (entry->type == CBM_SEQ) ||
           (entry->type == CBM_USR) ||
           (entry->type == CBM_REL) ||
           (entry->type == CBM_DISK_HDR));

    switch (entry->type)
    {
        case CBM_PRG:
            suffix = SUFFIX_PRG;
            break;

        case CBM_SEQ:
            suffix = SUFFIX_SEQ;
            break;
        
        case CBM_USR:
            suffix = SUFFIX_USR;
            break;
        
        case CBM_REL:
            suffix = SUFFIX_REL;
            break;
        
        case CBM_DISK_HDR:
            suffix = entry->cbm_header_id[0];
            delim = DELIM_HDR;
            break;

        default:
            assert(0);
        
    }

    // Sanity checks first
    assert(strnlen(entry->cbm_filename[0], MAX_CBM_FILENAME_STR_LEN) != MAX_CBM_FILENAME_STR_LEN);
    assert(MAX_FILENAME_LEN >= (MAX_CBM_FILENAME_STR_LEN + 1 + 4));

    // Construct the fuse_filename
    strncpy(entry->fuse_filename[0],
            entry->cbm_filename[0],
            MAX_CBM_FILENAME_STR_LEN);
    strncat(entry->fuse_filename[0],
            delim,
            1);
    strncat(entry->fuse_filename[0],
            suffix,
            3);

    DEBUG("EXIT: update_fuse_filename_from_cbm()");

    return;
}

// Update FUSE stat information, ready to provide it to FUSE when requested.
// Does this based on all of the other information in the cbm_file struct,
// which must be up to date and valid
static void update_fuse_stat(struct cbm_file *entry)
{
    off_t max_filesize;

    DEBUG("ENTRY: update_fuse_stat()");

    assert(entry != NULL);
    assert(entry->type != CBM_NONE);
    
    memset(&(entry->st), 0, sizeof(entry->st));

    // Set file size stuff
    // Num blocks is tricky.  It's supposed to represent the number of
    // 512 byte blocks.  But our filesystem has size 256 blocks.  So we
    // must convert into 512 byte blocks
    // Note that 
    switch (entry->type)
    {
        case CBM_PRG:
        case CBM_SEQ:
        case CBM_REL:
        case CBM_USR:
        case CBM_DISK_HDR:
            assert(CBM_BLOCK_SIZE == 256);
            max_filesize = CBM_BLOCK_SIZE * entry->cbm_blocks; 
            entry->st.st_blocks = (int)((max_filesize + 255) / 256 / 2);
            entry->st.st_blksize = CBM_BLOCK_SIZE;
            entry->st.st_size = max_filesize;
            break;

        case CBM_DUMMY_DIR:
        case CBM_DUMMY_FILE:
            entry->st.st_blksize = 512;
            entry->st.st_size = entry->filesize;
            entry->st.st_blocks = entry->filesize / entry->st.st_blksize;
            break;

        default:
            assert(0);
    }

    // Set other file mode and nlinks
    switch (entry->type)
    {
        case CBM_PRG:
        case CBM_SEQ:
        case CBM_REL:
        case CBM_USR:
        case CBM_DISK_HDR:
        case CBM_DUMMY_FILE:
            entry->st.st_mode |= S_IFREG | 0444;
            entry->st.st_nlink = 1;
            break;

        case CBM_DUMMY_DIR:
            entry->st.st_mode |= S_IFDIR | 0555;
            entry->st.st_nlink = 2;
            break;

        default:
            assert(0);
            break;
    }

    // Set timestamps - we leave dummy files with 0 timestamps, and actual
    // files on the disk (but not the file representing the header) as now.
    switch (entry->type)
    {
        case CBM_PRG:
        case CBM_SEQ:
        case CBM_REL:
        case CBM_USR:
            entry->st.st_atime = entry->st.st_ctime = entry->st.st_mtime = time(NULL);
            break;

        case CBM_DISK_HDR:
        case CBM_DUMMY_FILE:
        case CBM_DUMMY_DIR:
            // Do nothing - already set to 0.
            break;

        default:
            assert(0);
            break;
    }

    DEBUG("EXIT: update_fuse_stat()");

    return;
}

// Returns the next free file entry, and if necessary will reallocate the
// files array.
//
// Note that as this function may reallocate files, and file array entry
// pointers already held will be invalidated.
//
// Returns NULL if there are no more free file entries, and it was unable to
// reallocate memory for files.
struct cbm_file *get_next_free_file_entry(CBM *cbm)
{
    struct cbm_file *new_files;
    struct cbm_file *next_file;

    DEBUG("ENTRY: get_next_free_file_entry()");

    assert(cbm != NULL);
    assert(cbm->max_num_files >= cbm->num_files);
    
    if (cbm->max_num_files == cbm->num_files)
    {
        DEBUG("Will allocate %d more file entries",
              CBM_FILE_REALLOCATE_QUANTITY);
        new_files = realloc(cbm->files,
                            (cbm->max_num_files + CBM_FILE_REALLOCATE_QUANTITY) * sizeof(struct cbm_file));
        if (new_files != NULL)
        {
            cbm->files = new_files;
            memset(&cbm->files[cbm->max_num_files], 0,
                   CBM_FILE_REALLOCATE_QUANTITY * sizeof(struct cbm_file));
            cbm->max_num_files += CBM_FILE_REALLOCATE_QUANTITY;
        }
    }
    else
    {
        new_files = cbm->files;
    }

    if (new_files != NULL)
    {
        // memset to 0 even though it should already be 0 - belt and braces
        next_file = cbm->files + cbm->num_files;
        memset(next_file, 0, sizeof(*next_file));
    }
    else
    {
        next_file = NULL;
    }

    DEBUG("EXIT: get_next_free_file_entry()");

    return next_file;
}

// Frees up the provided file entry, and will rejig remaining file entries to ensure
// they are contiguous.
//
// Also frees up some memory (reallocating the entire array if there are more
// than CBM_FILE_REALLOCATE_QUANTITY * 2entries free in order to provide
// hysteresis
void free_file_entry(CBM *cbm, struct cbm_file *file)
{
    DEBUG("ENTRY: free_file_entry()");
    
    // Validate inputs
    assert(cbm != NULL);
    assert(file != NULL);
    assert(cbm->files != NULL);
    assert(cbm->num_files > 0);  // Must have at least one file to free
    assert(cbm->max_num_files >= cbm->num_files);
    
    // Check file pointer is within our array bounds AND properly aligned
    assert((file >= cbm->files) && 
           (file < (cbm->files + cbm->max_num_files)));
    // Check pointer arithmetic would give us a whole number
    assert(((long unsigned int)(file - cbm->files) * sizeof(struct cbm_file)) % 
           sizeof(struct cbm_file) == 0);

    // Calculate the index of the file to be removed
    size_t index = (long unsigned int)(file - cbm->files);
    assert(index < cbm->num_files);  // Must be within used portion
    
    // If this isn't the last entry, move all subsequent entries down
    // to maintain contiguous storage
    if (index < cbm->num_files - 1)
    {
        size_t entries_to_move = cbm->num_files - index - 1;
        memmove(&cbm->files[index], 
                &cbm->files[index + 1],
                entries_to_move * sizeof(struct cbm_file));
    }
    
    // Clear the now-unused last entry
    memset(&cbm->files[cbm->num_files - 1], 0, sizeof(struct cbm_file));
    cbm->num_files--;
    
    // Check if we should shrink the array
    // Only shrink if we have more than CBM_FILE_REALLOCATE_QUANTITY * 2
    // free entries to provide hysteresis
    // Also maintain minimum number
    if (((cbm->max_num_files - cbm->num_files) > 
         (CBM_FILE_REALLOCATE_QUANTITY * 2)) &&
            cbm->max_num_files > CBM_FILE_REALLOCATE_QUANTITY)
    {
        // Calculate the new maximum size by rounding up num_files to the next
        // multiple of CBM_FILE_REALLOCATE_QUANTITY.
        //
        // Example: if CBM_FILE_REALLOCATE_QUANTITY = 10:
        //   8 files -> new_max = 10
        //   11 files -> new_max = 20
        //   25 files -> new_max = 30
        // The adding of (CBM_FILE_REALLOCATE_QUANTITY-1) before division
        // achieves the round-up behavior using integer arithmetic which is
        // more efficient that fp math
        size_t new_max = ((cbm->num_files + CBM_FILE_REALLOCATE_QUANTITY - 1) 
                         / CBM_FILE_REALLOCATE_QUANTITY) 
                        * CBM_FILE_REALLOCATE_QUANTITY;
        
        // Ensure we don't go below minimum
        if (new_max < CBM_FILE_REALLOCATE_QUANTITY)
        {
            new_max = CBM_FILE_REALLOCATE_QUANTITY;
        }
            
        struct cbm_file *new_files = realloc(cbm->files, 
                                            new_max * sizeof(struct cbm_file));
        if (new_files != NULL)  // Only update if realloc succeeded
        {
            cbm->files = new_files;
            cbm->max_num_files = new_max;
        }
        // If realloc fails, we just keep the existing larger buffer
    }
    
    DEBUG("EXIT: free_file_entry()");

    return;
}

// Find a file entry based on its CBM filename, or its FUSE filename - but not
// both at the same time.
// Returns a pointer to the entry, or NULL if not found.
struct cbm_file *find_file_entry(CBM *cbm,
                                 char *cbm_filename,
                                 char *fuse_filename)
{
    char *filename;
    size_t max_filename_len;
    off_t offset;
    struct cbm_file *entry = NULL;

    DEBUG("ENTRY: find_file_entry()");

    assert(cbm != NULL);
    assert(cbm->max_num_files >= cbm->num_files);

    assert(!((cbm_filename != NULL) && (fuse_filename != NULL)));

    if (cbm_filename != NULL)
    {
        DEBUG("Find file based on CBM filename: %s", cbm_filename);
        filename = cbm_filename;
        max_filename_len = MAX_CBM_FILENAME_STR_LEN;
        offset = offsetof(struct cbm_file, cbm_filename);
    }
    else
    {
        assert(fuse_filename != NULL);
        DEBUG("Find file based on FUSE filename: %s", fuse_filename);
        filename = fuse_filename;
        max_filename_len = MAX_FUSE_FILENAME_STR_LEN;
        offset = offsetof(struct cbm_file, fuse_filename);
    }

    for (size_t ii = 0; ii < cbm->num_files; ii++)
    {
        if (!strncmp((char *)(&(cbm->files[ii]) + offset),
                     filename,
                     max_filename_len))
        {
            DEBUG("Found match at entry #%lu", ii);
            entry = &(cbm->files[ii]);
            break;
        }
    }

    DEBUG("EXIT: find_file_entry()");

    return entry;
}

inline struct cbm_file *find_cbm_file_entry(CBM *cbm,
                                            char *filename)
{
    return find_file_entry(cbm, filename, NULL);
}
inline struct cbm_file *find_dummy_file_entry(CBM *cbm,
                                              char *filename)
{
    return find_file_entry(cbm, NULL, filename);
}

// Returns the file type given the suffix.  Would be better as implemented
// as an array of mapping structs, but this was quicker.
static enum cbm_file_type get_cbm_file_type_from_suffix(const char *suffix)
{
    enum cbm_file_type type = CBM_NONE;

    DEBUG("ENTRY: get_cbm_file_type_from_suffix()");

   if (strlen(suffix) == ID_LEN)
    {
        // We have a header
        type = CBM_DISK_HDR;
    }
    else
    {
        if (strncmp(SUFFIX_PRG, suffix, CBM_FILE_TYPE_STR_LEN-1))
        {
            type = CBM_PRG;
        }
        else if (strncmp(SUFFIX_SEQ, suffix, CBM_FILE_TYPE_STR_LEN-1))
        {
            type = CBM_SEQ;
        }
        else if (strncmp(SUFFIX_SEQ, suffix, CBM_FILE_TYPE_STR_LEN-1))
        {
            type = CBM_USR;
        }
        else if (strncmp(SUFFIX_SEQ, suffix, CBM_FILE_TYPE_STR_LEN-1))
        {
            type = CBM_REL;
        }
    }

    DEBUG("EXIT: get_cbm_file_type_from_suffix()");

    return type;
}

// Creates a cbm_file array element
//
// Can be used for both CBM disk files (and the header), and for directories
// and files "invented" by 1541fs to display as part of the linux
// directory listing.
//
// Parses the filename and suffix, creates a cbm_file entry and returns a
// pointer to that entry.
//
// For a FUSE file suffix should be empty - any suffix should be passed in
// as part of the filename.  It is separate in the CBM case because it isn't
// part of the filename
//
// For a CBM file the information passed in has come straight from a directory
// listing so filename and suffix will be in PETSCII, and size will be number
// of CBM blocks, not bytes or FUSE 512 byte blocks.
//
// Directory must be 0 for CBM files.
//
// contents should only be provided for dummy files (not directories) and
// should be statically allocated - as it will never be freed
//
// This function may fail if we can't get a free entry (and can't reallocate
// in which case NULL is returned.  error will also be set in this case.
struct cbm_file *create_file_entry(CBM *cbm,
                                   const enum file_source source,
                                   const char *filename,
                                   const char *suffix,
                                   const int directory,
                                   const off_t size,
                                   const char *static_read_contents,
                                   int *error)
{
    struct cbm_file *entry = NULL;
    int rc =-1;
    size_t max_filename_len;

    DEBUG("ENTRY: create_file_entry()");

    // Check assumptions constraints on inputs
    assert(cbm != NULL);
    assert(filename != NULL);
    assert(error != NULL);
    assert((source == SOURCE_CBM) || (source == SOURCE_DUMMY));
    assert(((source == SOURCE_CBM) && (!directory)) ||
           (source == SOURCE_DUMMY));
    assert((static_read_contents == NULL) || (source == SOURCE_DUMMY));

    // Run some initial sanity checks on the data
    if (source == SOURCE_CBM)
    {
        max_filename_len = MAX_CBM_FILENAME_STR_LEN;
    }
    else
    {
        max_filename_len = MAX_FUSE_FILENAME_STR_LEN;
    }
    if (strlen(filename) >= max_filename_len)
    {
        DEBUG("Filename is too long: %s", filename);
        rc = -ENAMETOOLONG;
        goto EXIT;
    }

    if (suffix != NULL)
    {
        assert(source == SOURCE_CBM);
        assert(CBM_ID_STR_LEN <= CBM_FILE_TYPE_STR_LEN);
        assert(DUMMY_FILE_SUFFIX_LEN <= CBM_FILE_TYPE_STR_LEN);
        if (strnlen(suffix, CBM_FILE_TYPE_STR_LEN) >= CBM_FILE_TYPE_STR_LEN)
        {
            DEBUG("Suffix is too long: %s", suffix);
            rc = -ENAMETOOLONG;
            goto EXIT;
        }
    }
    else
    {
        assert(source == SOURCE_DUMMY);
    }

    // Now attempt to get an entry to fill in
    entry = get_next_free_file_entry(cbm);
    if (entry == NULL)
    {
        DEBUG("Failed to get a free file entry");
        rc = -ENOMEM;
        goto EXIT;
    }

    // Sort out filenames and entry type
    if (source == SOURCE_CBM)
    {
        strncpy(entry->cbm_filename[0],
                filename,
                CBM_FILE_TYPE_STR_LEN-1);
        // Don't need to bother with return code for cbm_petscii2ascii - it
        // changes the string in situ.
        cbm_petscii2ascii(entry->cbm_filename[0]);
        // Dummy files don't have trailing spaces to remove - only CBM ones do
        // Suffix should already have been stripped
        rc = remove_trailing_spaces(entry->cbm_filename[0]);
        assert(rc < MAX_CBM_FILENAME_STR_LEN-1);
        rc = -1; // reset error
        entry->type = get_cbm_file_type_from_suffix(suffix);
        if (entry->type == CBM_DISK_HDR)
        {
            strncpy(entry->cbm_header_id[0],
                    suffix,
                    CBM_ID_STR_LEN-1);
            cbm_petscii2ascii(entry->cbm_header_id[0]);
        }
        if (entry->type == CBM_NONE)
        {
            WARN("Unrecognised CBM file type: %s", suffix);
            rc = -EPROTO;
            free_file_entry(cbm, entry);
            entry = NULL;
            goto EXIT;
        }
        update_fuse_filename_from_cbm(entry);
    }
    else
    {
        strncpy(entry->cbm_filename[0],
                filename,
                CBM_FILE_TYPE_STR_LEN-1);
        if (directory)
        {
            assert(static_read_contents == NULL);
            entry->type = CBM_DUMMY_DIR;
        }
        else
        {
            entry->type = CBM_DUMMY_FILE;
        }
        strncpy(entry->fuse_filename[0], filename, CBM_ID_STR_LEN-1);
    }

    // Sort out filesizes (and contents)
    if (source == SOURCE_CBM)
    {
        entry->cbm_blocks = size;

        // We don't know the filesize yet - we've not read the completed file.
        // All we have right now is the num_blocks, so we know the filesize is
        // between 256 * (num_blocks-1) +1 and 256 * (num_blocks).
        entry->filesize = 0;
    }
    else
    {
        entry->static_read_contents = static_read_contents;
        if (entry->static_read_contents != NULL)
        {
            entry->filesize = (off_t)strlen(static_read_contents);
            assert((size == 0) || (size == entry->filesize));
        }
    }

    // Set stat, ready to be provided to FUSE when requested
    update_fuse_stat(entry);

    rc = 0;

EXIT:

    if ((entry = NULL) && (rc = 0))
    {
        rc = -1;
    }
    assert((entry != NULL) || (rc != 0));
    assert(!(entry != NULL) && !(rc != 0));
    *error = rc;

    DEBUG("EXIT: create_file_entry_cbm()");

    return entry;
}

inline struct cbm_file *create_cbm_file_entry(CBM *cbm,
                                              const char *filename,
                                              const char *suffix,
                                              const off_t cbm_blocks,
                                              int *error)
{
    return create_file_entry(cbm,
                             SOURCE_CBM,
                             filename,
                             suffix,
                             0,
                             cbm_blocks,
                             NULL,
                             error);
}

inline struct cbm_file *create_dummy_file_entry(CBM *cbm,
                                                const char *filename,
                                                const int directory,
                                                const off_t filesize,
                                                const char *static_read_contents,
                                                int *error)
{
    return create_file_entry(cbm,
                             SOURCE_DUMMY,
                             filename,
                             NULL,
                             directory,
                             filesize,
                             static_read_contents,
                             error);
}
