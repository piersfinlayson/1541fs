#include "cbmfuse.h"

// Allocate a free CBM channel, based on the required usage and free channels
int allocate_free_channel(CBM *cbm,
                          enum cbm_channel_usage usage,
                          struct cbm_file *entry)
{
    int min, max;
    int ch = -1;

    ENTRY();

    assert(cbm != NULL);
    assert(usage != USAGE_NONE);
    assert(entry != NULL);

    // Figure out valid channels based on usage
    switch (usage)
    {
        case USAGE_READ:
            min = 0;
            max = 0;
            break;

        case USAGE_WRITE:
            min = 1;
            max = 1;
            break;

        case USAGE_CONTROL:
            min = 15;
            max = 15;
            break;

        case USAGE_OPEN:
            min = MIN_USER_CHANNEL;
            max = MAX_USER_CHANNEL;
            break;

        default:
            assert(0);
            goto EXIT;
            break;
    }

    assert((min >= 0) && (min < NUM_CHANNELS));
    assert((max >= 0) && (max < NUM_CHANNELS));
    assert(min < max);

    // Find a free channel
    for (ch = min; ch <= max; ch++)
    {
        if (!cbm->channel[ch].open)
        {
            // Found a free channel
            DEBUG("Found a free channel: %d", ch);
            assert(cbm->channel[ch].num == ch);
            cbm->channel[ch].open = 1;
            cbm->channel[ch].usage = usage;
            cbm->channel[ch].file = entry;
            assert(entry->channel == NULL);
            entry->channel = &(cbm->channel[ch]);
            break;
        }
    }

    if (ch > max)
    {
        // Didn't find a valid channel
        ch = -1;
    }

EXIT:

    EXIT();

    return ch;
}

// To release an allocated channel.  Mustn't be used with a dummy channel
// (these aren't "allocated" in the first place)
void release_channel(CBM *cbm, int ch)
{
    assert(cbm != NULL);
    assert((ch >= 0) && (ch < NUM_CHANNELS));

    assert(cbm->channel[ch].num == ch);
    assert(cbm->channel[ch].open);
    assert(cbm->channel[ch].file != NULL);
    assert(cbm->channel[ch].file->channel == &(cbm->channel[ch]));

    // Clear up the file entry
    cbm->channel[ch].file->channel = NULL;
    cbm->channel[ch].file = NULL;
    
    // Check that any handles were cleared (because caller should have)
    // freed any allocated memory stored in them, etc
    assert(cbm->channel[ch].handle1 == NULL);
    assert(cbm->channel[ch].handle2 == 0);

    // Now memset this to 0 (yes, we explicitly set a bunch of stuff above
    // to zero but that was belt and braces, and this clears the rest)
    memset(&(cbm->channel[ch]), 0, sizeof(struct cbm_channel));
    cbm->channel[ch].num = (unsigned char)ch;

    assert(cbm->channel[ch].num == ch);
    assert(!cbm->channel[ch].open);
}

