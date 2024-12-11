#include "cbmfuse.h"

// Special paths
// Must not begin or terminate the / or FUSE will barf
const char *special_dirs[] =
{
    ".",
    "..",
    NULL
};

const char *special_files[] = {
    PATH_FORCE_DISK_REREAD,
    PATH_FORMAT_DISK,
    NULL,
};

// Removes any trailing spaces from the end of a string
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

int is_special_dir(const char *path)
{
    return is_special(path, special_dirs);
}

int is_special_file(const char *path)
{
    return is_special(path, special_files);
}

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

void destroy_files(CBM *cbm)
{
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
        next_file = cbm->files + cbm->num_files;
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