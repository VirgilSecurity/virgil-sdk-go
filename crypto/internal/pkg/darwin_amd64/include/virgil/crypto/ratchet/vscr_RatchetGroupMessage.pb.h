/* Automatically generated nanopb header */
/* Generated by nanopb-0.3.9.4 at Mon Dec 30 11:13:52 2019. */

#ifndef PB_VSCR_RATCHETGROUPMESSAGE_PB_H_INCLUDED
#define PB_VSCR_RATCHETGROUPMESSAGE_PB_H_INCLUDED
#include <pb.h>

/* @@protoc_insertion_point(includes) */
#if PB_PROTO_HEADER_VERSION != 30
#error Regenerate this file with the current version of nanopb generator.
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Struct definitions */
typedef struct _vscr_MessageGroupInfo {
    pb_byte_t session_id[32];
    uint32_t epoch;
    pb_byte_t key[32];
/* @@protoc_insertion_point(struct:vscr_MessageGroupInfo) */
} vscr_MessageGroupInfo;

typedef PB_BYTES_ARRAY_T(70) vscr_RegularGroupMessage_header_t;
typedef struct _vscr_RegularGroupMessage {
    vscr_RegularGroupMessage_header_t header;
    pb_byte_t signature[64];
    pb_bytes_array_t *cipher_text;
/* @@protoc_insertion_point(struct:vscr_RegularGroupMessage) */
} vscr_RegularGroupMessage;

typedef struct _vscr_RegularGroupMessageHeader {
    pb_byte_t session_id[32];
    uint32_t epoch;
    uint32_t prev_epochs_msgs[4];
    uint32_t counter;
/* @@protoc_insertion_point(struct:vscr_RegularGroupMessageHeader) */
} vscr_RegularGroupMessageHeader;

typedef struct _vscr_GroupMessage {
    uint32_t version;
    bool has_group_info;
    vscr_MessageGroupInfo group_info;
    bool has_regular_message;
    vscr_RegularGroupMessage regular_message;
/* @@protoc_insertion_point(struct:vscr_GroupMessage) */
} vscr_GroupMessage;

/* Default values for struct fields */

/* Initializer values for message structs */
#define vscr_MessageGroupInfo_init_default       {{0}, 0, {0}}
#define vscr_RegularGroupMessageHeader_init_default {{0}, 0, {0, 0, 0, 0}, 0}
#define vscr_RegularGroupMessage_init_default    {{0, {0}}, {0}, NULL}
#define vscr_GroupMessage_init_default           {0, false, vscr_MessageGroupInfo_init_default, false, vscr_RegularGroupMessage_init_default}
#define vscr_MessageGroupInfo_init_zero          {{0}, 0, {0}}
#define vscr_RegularGroupMessageHeader_init_zero {{0}, 0, {0, 0, 0, 0}, 0}
#define vscr_RegularGroupMessage_init_zero       {{0, {0}}, {0}, NULL}
#define vscr_GroupMessage_init_zero              {0, false, vscr_MessageGroupInfo_init_zero, false, vscr_RegularGroupMessage_init_zero}

/* Field tags (for use in manual encoding/decoding) */
#define vscr_MessageGroupInfo_session_id_tag     1
#define vscr_MessageGroupInfo_epoch_tag          2
#define vscr_MessageGroupInfo_key_tag            3
#define vscr_RegularGroupMessage_header_tag      1
#define vscr_RegularGroupMessage_signature_tag   2
#define vscr_RegularGroupMessage_cipher_text_tag 3
#define vscr_RegularGroupMessageHeader_session_id_tag 1
#define vscr_RegularGroupMessageHeader_epoch_tag 2
#define vscr_RegularGroupMessageHeader_prev_epochs_msgs_tag 3
#define vscr_RegularGroupMessageHeader_counter_tag 4
#define vscr_GroupMessage_version_tag            1
#define vscr_GroupMessage_group_info_tag         2
#define vscr_GroupMessage_regular_message_tag    3

/* Struct field encoding specification for nanopb */
extern const pb_field_t vscr_MessageGroupInfo_fields[4];
extern const pb_field_t vscr_RegularGroupMessageHeader_fields[5];
extern const pb_field_t vscr_RegularGroupMessage_fields[4];
extern const pb_field_t vscr_GroupMessage_fields[4];

/* Maximum encoded size of messages (where known) */
#define vscr_MessageGroupInfo_size               74
#define vscr_RegularGroupMessageHeader_size      70
/* vscr_RegularGroupMessage_size depends on runtime parameters */
/* vscr_GroupMessage_size depends on runtime parameters */

/* Message IDs (where set with "msgid" option) */
#ifdef PB_MSGID

#define VSCR_RATCHETGROUPMESSAGE_MESSAGES \


#endif

#ifdef __cplusplus
} /* extern "C" */
#endif
/* @@protoc_insertion_point(eof) */

#endif
