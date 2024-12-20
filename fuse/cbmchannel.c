#include "cbmfuse.h"

// Allocate a free CBM channel, based on the required usage and free channels
// entry may be NULL, in which case the channel _must_ be allocated and then
// released within a single FUSE callback (as the file entry is the only way
// to keep track of channels across FUSE callbacks
int allocate_free_channel(CBM *cbm,
                          enum cbm_channel_usage usage,
                          struct cbm_file *entry)
{
    int min, max;
    int ch = -1;

    ENTRY();

    assert(cbm != NULL);
    assert(usage != USAGE_NONE);

    // Figure out valid channels based on usage
    switch (usage)
    {
        case USAGE_LOAD:
            min = LOAD_CHANNEL;
            max = LOAD_CHANNEL;
            break;

        case USAGE_SAVE:
            min = SAVE_CHANNEL;
            max = SAVE_CHANNEL;
            break;

        case USAGE_COMMAND:
            min = COMMAND_CHANNEL;
            max = COMMAND_CHANNEL;
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
    assert(min <= max);

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
            if (entry != NULL)
            {
                assert(entry->channel == NULL);
                entry->channel = &(cbm->channel[ch]);
            }
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
    struct cbm_channel *channel;

    ENTRY();

    assert(cbm != NULL);
    assert((ch >= 0) && (ch < NUM_CHANNELS));

    channel = cbm->channel + ch;

    assert(channel->num == ch);
    assert(channel->open);
    if (channel->file != NULL)
    {
        // Clear up the file entry
        assert(channel->file->channel == &(cbm->channel[ch]));
        channel->file->channel = NULL;
        channel->file = NULL;
    }
    
    // Check that any handles were cleared (because caller should have)
    // freed any allocated memory stored in them, etc
    assert(channel->handle1 == NULL);
    assert(channel->handle2 == 0);

    // Now memset this to 0 (yes, we explicitly set a bunch of stuff above
    // to zero but that was belt and braces, and this clears the rest)
    memset(channel, 0, sizeof(struct cbm_channel));
    channel->num = (unsigned char)ch;

    assert(channel->num == ch);
    assert(!channel->open);

    EXIT();

    return;
}