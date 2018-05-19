#pragma once
#include <rawrtc.h>
#include "common.h"

/*
 * Convert string to uint16.
 */
bool str_to_uint16(
    uint16_t* const numberp,
    char* const str
);

/*
 * Get a dictionary entry and store it in `*valuep`.
 */
enum rawrtc_code dict_get_entry(
    void* const valuep,
    struct odict* const parent,
    char* const key,
    enum odict_type const type,
    bool required
);

/*
 * Get a uint32 entry and store it in `*valuep`.
 */
enum rawrtc_code dict_get_uint32(
    uint32_t* const valuep,
    struct odict* const parent,
    char* const key,
    bool required
);

/*
 * Get a uint16 entry and store it in `*valuep`.
 */
enum rawrtc_code dict_get_uint16(
    uint16_t* const valuep,
    struct odict* const parent,
    char* const key,
    bool required
);

/*
 * Get JSON from stdin and parse it to a dictionary.
 */
enum rawrtc_code get_json_stdin(
    struct odict** const dictp // de-referenced
);

/*
 * Get the ICE role from a string.
 */
enum rawrtc_code get_ice_role(
    enum rawrtc_ice_role* const rolep, // de-referenced
    char const* const str
);

/*
 * Create a data channel helper instance.
 */
void data_channel_helper_create(
    struct data_channel_helper** const channel_helperp, // de-referenced
    struct client* const client,
    char* const label
);

/*
 * Create a data channel helper instance from parameters.
 */
void data_channel_helper_create_from_channel(
    struct data_channel_helper** const channel_helperp, // de-referenced
    struct rawrtc_data_channel* channel,
    struct client* const client,
    void* const arg // nullable
);
