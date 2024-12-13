#include "cbmfuse.h"

// Contains code for dealing with cbm_file entries

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

// Allocate/realloc buffer
// Can be passed a zero length buffer and zero buflen 
static void *realloc_buffer(char *buffer,
                            const size_t buflen,
                            size_t *newlen)
{
    char *new_buffer;

    assert(newlen != NULL);

    *newlen = buflen + BUF_INC;
    new_buffer = realloc(buffer, *newlen);
    if (new_buffer == NULL)
    {
        WARN("Failed to realloc buffer was %zu attemped %zu", buflen, *newlen);
        *newlen = 0;
    }

    return new_buffer;
}

// Load the directory listing from disk - might be able to use the regular
// read function for this
static int load_dir_listing(CBM *cbm, char **buf, size_t *data_len)
{
    int rc = 1;
    int rc2;
    char *buffer;
    size_t buf_len;
    size_t pos;
    char c;
    int drive_open = 0;

    ENTRY();

    *buf = NULL;

    // malloc a buffer to store data read from the disk in
    DEBUG("Allocate buffer to read in data");
    buffer = realloc_buffer(NULL, 0, &buf_len);
    if (buffer == NULL)
    {
        DEBUG("Failed to allocate memory for buffer to read dir into");
        rc = -ENOMEM;
        goto EXIT;
    }
    assert(buf_len > 0);

    // open the directory "file" ($)
    DEBUG("Open $");
    c = cbm_ascii2petscii_c('$');
    rc = cbm_open(cbm->fd, cbm->device_num, 0, &c, READ_CHANNEL);
    if (rc)
    {
        rc2 = check_drive_status(cbm);
        DEBUG("Open of $ failed %d", rc);
        DEBUG("Drive status %d %s", rc2, cbm->error_buffer);
        goto EXIT;
    }
    drive_open = 1;
    cbm_talk(cbm->fd, cbm->device_num, 0);

    // Read in directory listing from the drive
    DEBUG("Read in directory data");
    pos = 0;
    while (cbm_raw_read(cbm->fd, buffer + pos, 1) == 1)
    {
        pos++;
        if (pos >= buf_len)
        {
            buffer = realloc_buffer(buffer, buf_len, &buf_len);
            if (buffer == NULL)
            {
                DEBUG("Out of memory while reading directory");
                rc = -ENOMEM;
                goto EXIT;
            }
        }
    }
    *data_len = pos;
    DEBUG("Read %zu bytes total directory listing", *data_len);

    rc = cbm_untalk(cbm->fd);
    if (rc)
    {
        rc2 = check_drive_status(cbm);
        DEBUG("Hit error reading $ from disk %d", rc);
        DEBUG("Drive status %d %s", rc2, cbm->error_buffer);
        goto EXIT;
    }

    *buf = buffer;

EXIT:

    if (drive_open)
    {
        cbm_close(cbm->fd, cbm->device_num, 0);
    }

    if (rc)
    {
        free(buffer);
        *buf = NULL;
        *data_len = 0;
    }

    EXIT();

    return rc;
}

static int process_dir_listing(CBM *cbm, char *buffer, size_t data_len)
{
    int rc = 1;
    size_t pos;
    int line_count;

    ENTRY();

    assert(cbm != NULL);
    assert(buffer != NULL);

    // Check 1st 3 bytes
    DEBUG("Check 1st 4 bytes of listing");
    pos = 0;
    if (data_len < 4)
    {
        DEBUG("Fewer than 4 bytes in whole dir listing");
        goto EXIT;
    }
    unsigned char first_4_bytes[4] = {0x1, 0x4, 0x1, 0x01};
    if (memcmp(buffer, first_4_bytes, 4))
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
    line_count = 0;
    while (pos < data_len)
    {
        struct cbm_file *entry;
        off_t cbm_blocks;
        DEBUG("Reading line of listing");

        DEBUG("Get blocks for this file");
        // Get the number of blocks for this file
        if (pos >= (data_len + 2))
        {
            DEBUG("Ran out of data too soon");
            goto EXIT;
        }
        DEBUG("Next 2 bytes for block size: 0x%x 0x%x", (unsigned char)buffer[pos], (unsigned char)buffer[pos+1]);
        cbm_blocks = (unsigned char)buffer[pos++];
        // If the 2nd byte is 0x12 that means reverse text - so header
        // Assume any value below this is high order byte, any value
        // above this isn't.
        if (buffer[pos] < 0x12)
        {
            cbm_blocks |= (unsigned short)(buffer[pos++] << 8);
        }
        DEBUG("Num blocks: %zu", cbm_blocks);

        // Now read the rest of the line
        DEBUG("Read rest of line data");
        char filename[MAX_CBM_FILENAME_STR_LEN];
        char suffix[CBM_FILE_TYPE_STR_LEN];
        int filename_started = 0;
        int filename_ended = 0;
        int filename_len = 0;
        int is_header = 0;
        int is_footer = 0;
        int suffix_ended = 0;
        int suffix_len = 0;
        memset(filename, 0, sizeof(filename));
        memset(suffix, 0, sizeof(suffix));
        while ((pos < data_len) && 
               (buffer[pos] != 0x1))
        {
            char c;
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
                    filename[filename_len] = 0;
                    filename_ended = 1;
                }
                else
                {
                    DEBUG("Add char to filename: %c", c);
                    // Any other char just gets added to the filename
                    // We'll cope with trailing spaces when appending the .XXX
                    // suffix
                    // We save 4 chars for the 3 digit suffix and 1xNULL terminator
                    if (filename_len < (MAX_FUSE_FILENAME_STR_LEN - 4))
                    {
                        filename[filename_len++] = c;
                    }
                    else
                    {
                        WARN("Filename is longer than max len - truncated version is: %s",
                             filename);
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
                    suffix[suffix_len] = 0;
                    suffix_ended = 1;
                }
                else if (suffix_len < 3)
                {
                    DEBUG("Add char to suffix: %c", c);
                    suffix[suffix_len++] = c;
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


        // Don't add the footer
        if (!is_footer)
        {
            // Now we have the info, create the file entry
            entry = create_cbm_file_entry(cbm,
                                          filename,
                                          suffix,
                                          cbm_blocks,
                                          &disk_cbs,
                                          &rc);
            if (entry == NULL)
            {
                WARN("Couldn't create a file entry for %s %s %d", filename, suffix, rc);
                assert(rc != 0);
                goto EXIT;
            }

            DEBUG("Added disk file entry #%d: type %d fuse filename %s size %zu cbm blocks %zu",
                line_count,
                entry->type,
                entry->fuse_filename,
                entry->filesize,
                entry->cbm_blocks);

            line_count++;
        }

        // Don't add the footer
        if (pos >= (data_len + 2))
        {
            DEBUG("Not enough data to read another line - exiting line parsing");
        }
        // Next two bytes should be 0x1 and 0x1, or 0x0 and 0x0 after footer
        DEBUG("Skipping next 2 bytes: 0x%d 0x%d", buffer[pos], buffer[pos+1]);
        pos += 2;
    }

    rc = 0;

EXIT:

    if (!rc) // Succeeded!
    {
        DEBUG("Number of directory entries read: %d", line_count);
    }

    EXIT();

    return rc;
}

int read_dir_from_disk(CBM *cbm)
{
    int rc = -1;
    char *buf;
    size_t data_len;

    ENTRY();

    assert(cbm != NULL);

    cbm->dir_is_clean = 0;

    rc = load_dir_listing(cbm, &buf, &data_len);
    if (rc < 0)
    {
        goto EXIT;
    }

    rc = process_dir_listing(cbm, buf, data_len);
    free(buf);
    if (rc)
    {
        goto EXIT;
    }

    cbm->dir_is_clean = 1;
    rc = 0;

#ifdef DEBUG_BUILD
    log_file_entries(cbm);
#endif // DEBUG_BUILD

EXIT:

    EXIT();

    return rc;
}

// Frees up any memory associated with file entrys in cbm_state.
void destroy_files(CBM *cbm)
{
    ENTRY();

    if (cbm->files != NULL)
    {
        for (int ii = 0; ii < NUM_CHANNELS; ii++)
        {
            if (cbm->channel[ii].handle1 != NULL)
            {
                DEBUG("Freeing buffer from channel %d", ii);
                free(cbm->channel[ii].handle1);
                cbm->channel[ii].handle1 = NULL;
                cbm->channel[ii].handle2 = 0;
            }
        }
        free(cbm->files);
        cbm->files = NULL;
    }

    EXIT();
}

// Returns the file type given the suffix.  Would be better as implemented
// as an array of mapping structs, but this was quicker.
static enum cbm_file_type get_cbm_file_type_from_suffix(const char *suffix)
{
    enum cbm_file_type type = CBM_NONE;

    ENTRY();

    if (strlen(suffix) == CBM_ID_LEN)
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

    EXIT();

    return type;
}

// Fills in the cbm_filename given a fuse_filename in a cbm_file struct
// Handles figuring out if the file suffix is valid, etc
// Returns 0 on success. 
static int update_cbm_filename_from_fuse(struct cbm_file *entry)
{
    int rc = -1;
    char cbm_suffix[CBM_FILE_TYPE_STR_LEN];
    char *filename;
    size_t filename_len;
    size_t suffix_len;
    int ii; 

    ENTRY();

    assert(entry != NULL);
    filename = entry->fuse_filename;
    filename_len = strlen(filename);

    // We already checked this
    assert(filename_len < MAX_FUSE_FILENAME_STR_LEN);

    // We use an int for ii because theoretically ii could start at -1
    // with a zero length string, which itself is maybe possible
    // We're searching backwards through the fuse filename in order to find
    // the . delimiter, as the part following the delimiter shows us the
    // CBM file type
    suffix_len = 0;
    for (ii = (int)(filename_len-1); ii >= 0; ii--)
    {
        if (filename[ii] == '.')
        {
            // suffix_len shows us the length of the suffix!
            if (suffix_len != CBM_FILE_TYPE_LEN)
            {
                DEBUG("Invalid suffix length %d should be %d",
                        ii,
                        CBM_FILE_TYPE_LEN);
                rc = -EPROTO;
                goto EXIT;
            }

            // Copy the suffix temporarily to cbm_suffix
            assert(suffix_len < CBM_FILE_TYPE_STR_LEN);
            strcpy(cbm_suffix, filename+ii+1);

            // Remove the suffix from the filename by NULL terminating at
            // the delimiter
            filename[ii] = 0;
            assert(ii >= 0);
            filename_len = (size_t)ii;
            break;
        }
        suffix_len++;
    }

    if (ii >= 0)
    {
        // We found the suffix (i.e. we broke out of the for loop before ii
        // hit -1)
        // Copy the fileame (which now doesn't have the suffix) into
        // cbm_filename
        assert(filename_len < MAX_CBM_FILENAME_STR_LEN);
        strcpy(entry->cbm_filename, filename);

        // Now convert it to PETSCII as that's how we store cbm_filename
        cbm_ascii2petscii(entry->cbm_filename);
    }
    DEBUG("Have cbm_filename of %s and suffix of %s",
          entry->cbm_filename,
          cbm_suffix);

    entry->type = get_cbm_file_type_from_suffix(cbm_suffix);
    switch (entry->type)
    {
        case CBM_PRG:
        case CBM_SEQ:
        case CBM_USR:
        case CBM_REL:
            rc = 0;
            break;

        default:
            DEBUG("Suffix is an invalid CBM file type: %s", cbm_suffix);
            rc = -EPROTO;
            goto EXIT;
            break;
    }

EXIT:

    return rc;
} 

// Fills in the fuse_filename field in a cbm_file struct, assuming that the
// cbm_filename, header_id (if type == CBM_DISK_HDR) and type fields are set.
static void update_fuse_filename_from_cbm(struct cbm_file *entry)
{
    char *suffix;
    char delim_char = DELIM_FILE;
    size_t filename_len;
    size_t suffix_len;

    ENTRY();

    assert(entry != NULL);
    assert((entry->type == CBM_PRG) ||
           (entry->type == CBM_SEQ) ||
           (entry->type == CBM_USR) ||
           (entry->type == CBM_REL) ||
           (entry->type == CBM_DISK_HDR));

    switch (entry->type)
    {
        case CBM_PRG:
            suffix = SUFFIX_PRG_LOWER;
            break;

        case CBM_SEQ:
            suffix = SUFFIX_SEQ_LOWER;
            break;
        
        case CBM_USR:
            suffix = SUFFIX_USR_LOWER;
            break;
        
        case CBM_REL:
            suffix = SUFFIX_REL_LOWER;
            break;
        
        case CBM_DISK_HDR:
            suffix = entry->cbm_header_id;
            delim_char = DELIM_HDR;
            break;

        default:
            assert(0);
        
    }

    // Construct the fuse_filename - first the bit before the delimiter
    filename_len = strlen(entry->cbm_filename);
    assert(filename_len < MAX_CBM_FILENAME_STR_LEN);
    assert(MAX_CBM_FILENAME_STR_LEN <= MAX_FUSE_FILENAME_STR_LEN);
    strcpy(entry->fuse_filename, entry->cbm_filename);
    cbm_petscii2ascii(entry->fuse_filename);

    // Now the delimiter
    assert(MAX_FUSE_FILENAME_STR_LEN >= (MAX_CBM_FILENAME_STR_LEN + 1));
    entry->fuse_filename[filename_len++] = delim_char;

    // Now add the suffix
    assert(MAX_FUSE_FILENAME_STR_LEN >= (MAX_CBM_FILENAME_STR_LEN + 1 + 3));
    suffix_len = strnlen(suffix, 4);
    assert(suffix_len < 4);
    strcpy(entry->fuse_filename+filename_len, suffix);
    filename_len += suffix_len;
    assert(filename_len < MAX_FUSE_FILENAME_STR_LEN);

    EXIT();

    return;
}

// Update FUSE stat information, ready to provide it to FUSE when requested.
// Does this based on all of the other information in the cbm_file struct,
// which must be up to date and valid
static void update_fuse_stat(struct cbm_file *entry)
{
    off_t max_filesize;

    ENTRY();

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

    EXIT();

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

    ENTRY();

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

    cbm->num_files++;

    EXIT();

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
    ENTRY();
    
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
    
    EXIT();

    return;
}

// Find a file entry based on its CBM filename, or its FUSE filename - but not
// both at the same time.
// Returns a pointer to the entry, or NULL if not found.
struct cbm_file *find_file_entry(CBM *cbm,
                                 const char *cbm_filename,
                                 const char *fuse_filename)
{
    const char *filename;
    size_t max_filename_len;
    off_t offset;
    struct cbm_file *entry = NULL;

    ENTRY();

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
        if (!strncmp(((char *)(&(cbm->files[ii])) + offset),
                     filename,
                     max_filename_len))
        {
            DEBUG("Found match at entry #%lu", ii);
            entry = &(cbm->files[ii]);
            break;
        }
    }

    EXIT();

    return entry;
}

inline struct cbm_file *find_cbm_file_entry(CBM *cbm,
                                            const char *filename)
{
    return find_file_entry(cbm, filename, NULL);
}
inline struct cbm_file *find_fuse_file_entry(CBM *cbm,
                                             const char *filename)
{
    return find_file_entry(cbm, NULL, filename);
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
                                   struct callbacks *cbs,
                                   int *error)
{
    struct cbm_file *entry = NULL;
    int rc =-1;
    int rc2;
    size_t max_filename_len;
    size_t suffix_len;

    ENTRY();
    PARAMS("Source %d Filename %s Directory %d Size %jd Cbs 0x%p",
           source,
           filename,
           directory,
           size,
           (void *)cbs);

    // Processing
    // * Checks
    // * Get a free cbm_file entry 
    // * Store off the name
    // * Figure out the type
    // * Store off size information
    // * Create stat information
    // If anything goes wrong free the cbm_file entry and return the error
    // code

    // Check assumptions constraints on inputs
    assert(cbm != NULL);
    assert(filename != NULL);
    assert(error != NULL);
    assert((source == SOURCE_CBM) ||
           (source == SOURCE_DUMMY) ||
           (source == SOURCE_FUSE));
    assert((!directory) || (source == SOURCE_DUMMY));

    // Name processing differs for different sources and storage type
    // * cbm_filename and cbm_header_id are stored as PETSCII
    // * fuse_filename is stored as ASCII
    // * If the source is SOURCE_DUMMY or SOURCE_FUSE we are provided
    //   a fuse_filename (in ASCII)
    // * If the source is SOURCE_CBM it's a fuse_filename (in PETSCII)
    // * For a SOURCE_FUSE file we need to create cbm_filename (PETSCII)
    // * For a SOURCE_CBM file we need to create the fuse_filename (ASCII)
    // * for a SOURCE_DUMMY file we don't need a cbm_filename as we'll never
    //   represent it on disk

    // Run some initial sanity checks on the name data
    if (source == SOURCE_CBM)
    {
        max_filename_len = MAX_CBM_FILENAME_STR_LEN;
    }
    else
    {
        // FUSE and DUMMY files have the same filename length limit
        max_filename_len = MAX_FUSE_FILENAME_STR_LEN;
    }
    if (strnlen(filename, max_filename_len) >= max_filename_len)
    {
        DEBUG("Filename is too long: %s %jd limit",
              filename,
              max_filename_len-1);
        rc = -ENAMETOOLONG;
        goto EXIT;
    }
    if (suffix != NULL)
    {
        // Only souce CBM has a suffix provided separately - it's part of the
        // filename FUSE/DUMMY (linux) case
        assert(source == SOURCE_CBM);
        PARAMS("Suffix: %s", suffix);

        // The ID suffix is 2 bytes, the file type suffix is 3
        // So the suffix should be 3 or fewer bytes 
        assert(CBM_ID_STR_LEN <= CBM_FILE_TYPE_STR_LEN);
        suffix_len = strnlen(suffix, CBM_FILE_TYPE_STR_LEN); 
        if (suffix_len >= CBM_FILE_TYPE_STR_LEN)
        {
            DEBUG("Suffix is too long: %s %d limit", 
                  suffix,
                  CBM_FILE_TYPE_STR_LEN);
            rc = -ENAMETOOLONG;
            goto EXIT;
        }
        else if (suffix_len < CBM_ID_LEN)
        {
            DEBUG("Suffix is too short: %s %zu %d limit",
                  suffix,
                  suffix_len,
                  CBM_ID_LEN);
            rc = -EPROTO;  // There isn't a too short error
            goto EXIT;
        }
    }

    // Now that we've done some checks on the filename and suffix we can
    // attempt to get an entry to fill in
    entry = get_next_free_file_entry(cbm);
    if (entry == NULL)
    {
        DEBUG("Failed to get a free file entry");
        rc = -ENOMEM;
        goto EXIT;
    }

    // File in the filenames and figure out the cbm_file_type
    // Do this as a switch to make it more readable than if/else
    switch(source)
    {
        case SOURCE_CBM:
            // We know the filename will fit
            assert(strlen(filename) < MAX_CBM_FILENAME_STR_LEN);
            strcpy(entry->cbm_filename, filename);

            // Leave as PETSCII but remove any trailing spaces
            // Return code is the new string length
            // Note it could be zero length (if the filename is all spaces)
            rc2 = remove_trailing_spaces(entry->cbm_filename);
            assert(rc2 <= MAX_CBM_FILENAME_STR_LEN - 1);

            // Get the cbm_file_type
            entry->type = get_cbm_file_type_from_suffix(suffix);
            switch (entry->type)
            {
                case CBM_DISK_HDR:
                    assert(strlen(suffix) < CBM_ID_STR_LEN);
                    strcpy(entry->cbm_header_id, suffix);

                case CBM_PRG:
                case CBM_SEQ:
                case CBM_REL:
                case CBM_USR:
                    ;
                    break;

                default:
                    // Code after EXIT: label will free entry
                    WARN("Unrecognised CBM file type %s - ignoring file",
                         suffix);
                    rc = -EPROTO;
                    goto EXIT;
                    break;
            }

            // Create the FUSE filename given the CBM one
            update_fuse_filename_from_cbm(entry);
            break;

        case SOURCE_DUMMY:
            // We've already checked the filename length
            strcpy(entry->fuse_filename, filename);
            entry->type = directory ? CBM_DUMMY_DIR : CBM_DUMMY_FILE;
            break;

        case SOURCE_FUSE:
            // We've already checked the filename length
            strcpy(entry->fuse_filename, filename);
            rc2 = update_cbm_filename_from_fuse(entry);
            if (!rc2)
            {
                DEBUG("Failed to convert fuse filename to CBM %d", rc);
                rc = -EPROTO;
                goto EXIT;
            }
            break;

        default:
            // Invalid source
            assert(0);
    }

    // Similar to name, size differs depending on the source
    // * For a SOURCE_CBM it's the number of CBM (256 byte) blocks
    //   Size in stat is calculated (estimated) by multiplying the number
    //   of full blocks with 256 bytes.  This is an over-estimate.  When
    //   the file is read from disk, we will get an accurate figure and
    //   update the filesize.  However, when a disk read happens again we
    //   will update with an estimate - as we don't know if the accurate
    //   figure is still valid
    // * For a SOURCE_DUMMY file it's the size represented in the FUSE
    //   filesystem, and can be a made up number (although that can confuse
    //   FUSE if and when it tries to read the file)
    // * For a SOURCE_FUSE file it's the size written by FUSE - i.e. its
    //   actual size.  A SOURCE_FUSE file will be deleted once the file is
    //   written to disk and then re-read as part of a directory listing

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
        entry->filesize = size;
    }

    // Set stat, ready to be provided to FUSE when requested
    update_fuse_stat(entry);

    // Set the callbacks - may be NULL in which case that function won't be
    // supported for this file, and FUSE operations will be rejected
    memcpy(&(entry->cbs), cbs, sizeof(*cbs));

    rc = 0;

EXIT:

    if (entry == NULL)
    {
        // If entry is NULL we must have hit an error
        assert(rc);
    }
    else
    {
        if (rc != 0)
        {
            // We hit an error after allocating a file entry - free it
            DEBUG("Hit error processing entry - free it");
            free_file_entry(cbm, entry);
        }
    } 
    *error = rc;

    EXIT();

    return entry;
}

inline struct cbm_file *create_cbm_file_entry(CBM *cbm,
                                              const char *filename,
                                              const char *suffix,
                                              const off_t cbm_blocks,
                                              struct callbacks *cbs,
                                              int *error)
{
    return create_file_entry(cbm,
                             SOURCE_CBM,
                             filename,
                             suffix,
                             0,
                             cbm_blocks,
                             cbs,
                             error);
}

inline struct cbm_file *create_fuse_file_entry(CBM *cbm,
                                               const char *filename,
                                               const off_t filesize,
                                               struct callbacks *cbs,
                                               int *error)
{
    return create_file_entry(cbm,
                             SOURCE_FUSE,
                             filename,
                             NULL,
                             0,
                             filesize,
                             cbs,
                             error);
}

inline struct cbm_file *create_dummy_file_entry(CBM *cbm,
                                                const char *filename,
                                                const int directory,
                                                const off_t filesize,
                                                struct callbacks *cbs,
                                                int *error)
{
    return create_file_entry(cbm,
                             SOURCE_DUMMY,
                             filename,
                             NULL,
                             directory,
                             filesize,
                             cbs,
                             error);
}

int is_dummy_file(struct cbm_file *entry)
{
    int is_it;

    // ENTRY();

    assert(entry != NULL);

    switch (entry->type)
    {
        case CBM_DISK_HDR:
        case CBM_DUMMY_DIR:
        case CBM_DUMMY_FILE:
            is_it = 1;
            break;

        default:
            is_it = 0;
            break;
    }

    // EXIT();

    return is_it;
}

#ifdef DEBUG_BUILD
// Make DEBUG logs, one for each cbm_file entry
void log_file_entries(CBM *cbm)
{
    struct cbm_file *e;
    char *format_str;

    assert(cbm != NULL);

    ENTRY();

    // The code here is very tedious.  Different platforms have different
    // size st_blksize and st_nlink.  On x86 I've found them to be 8 bytes
    // (longs).  However on ARM64, they are 4 bytes.  So, we need to use
    // different format specifiers.  This code assumes they are the same
    // size.  I guess it's possible the kernel has been compiled with them
    // being different sizes,  in which case these asserts will fire.
    // As they will if anything other than 4 and 8 byte sized versions are
    // used.
    // Also GCC throws a git if you don't use a static defined format
    // specifier and are using the -Wformat-nonliteral (and have warnings
    // as errors).  So we need to disable this warning.
    // It might be feasible just to use %zu on platforms that use 4 byte
    // sizes, but then again it might not.  So I'm taking this approach.
    // All of this just to do some logging!
    for (int ii = 0; ii < (int)(cbm->num_files); ii++)
    {
        e = cbm->files+ii;
        if (sizeof(e->st.st_blksize) == 4)
        {
            assert(sizeof(e->st.st_nlink) == 4);
            format_str =
                "%s File entry: Type %d CBM %s FUSE %s cbm_blocks %jd "
                "filesize %jd not_yet_on_disk %d channel 0x%p "
                "st_size %zu st_blocks %jd st_blksize %u",
                " st_mode: 0%o, st_nlink: %u"; 
        }
        else
        {
            assert(sizeof(e->st.st_blksize) == 8);
            assert(sizeof(e->st.st_blksize) == 8);
            format_str =
                "%s File entry: Type %d CBM %s FUSE %s cbm_blocks %jd "
                "filesize %jd not_yet_on_disk %d channel 0x%p "
                "st_size %zu st_blocks %jd st_blksize %zu",
                " st_mode: 0%o, st_nlink: %zu"; 
        }
#pragma GCC diagnostic push 
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
        DEBUG_NO_PAD(format_str,
                     PAD,
                     e->type,
                     e->cbm_filename,
                     e->fuse_filename,
                     e->cbm_blocks,
                     e->filesize,
                     e->not_yet_on_disk,
                     (void*)(e->channel),
                     e->st.st_size,
                     e->st.st_blocks,
                     e->st.st_blksize,
                     e->st.st_mode,
                     e->st.st_nlink);
#pragma GCC diagnostic pop
    }

    EXIT();

    return;
}
#endif // DEBUG_BUILD