#include "cbmfuse.h"

// Thread function to read a disk directory.  Spawned by
// cbm_create_read_dir_thread()
static void *read_dir_from_disk_thread_func(void *vargp)
{
    CBM *cbm;
    int rc;

    ENTRY();
    
    assert(vargp != NULL);
    cbm = (CBM *)vargp;
    assert(cbm != NULL);

    pthread_mutex_lock(&(cbm->mutex));
    rc = read_dir_from_disk(cbm);
    pthread_mutex_unlock(&(cbm->mutex));

    // Ignore the return code - there's nothing we can do here, and 
    // read_dir_from_disk logs any errors itself 
    (void)rc;

    EXIT();

    return NULL;
}

// Used to kick off a read of the directory listing in a separate thread.
//
// Is done by cbm_init() once initialization is complete, in a separate thread
// to speed up performance of subsequent directory/file reads by either the
// kernel or user.
// Is also done at other times, as the code chooses, normally when the code
// suspects the directory contents have changed.
void cbm_create_read_dir_thread(CBM *cbm)
{
    ENTRY();
    pthread_t thread_id;
    pthread_create(&thread_id,
                    NULL,
                    read_dir_from_disk_thread_func,
                    (void *)cbm);
    EXIT();
}

