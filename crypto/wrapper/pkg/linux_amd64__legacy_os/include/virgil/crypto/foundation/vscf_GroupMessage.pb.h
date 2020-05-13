/* Automatically generated nanopb header */
/* Generated by nanopb-0.3.9.4 at Wed May 13 09:34:47 2020. */

#ifndef PB_VSCF_GROUPMESSAGE_PB_H_INCLUDED
#define PB_VSCF_GROUPMESSAGE_PB_H_INCLUDED
#include <pb.h>

/* @@protoc_insertion_point(includes) */
#if PB_PROTO_HEADER_VERSION != 30
#error Regenerate this file with the current version of nanopb generator.
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Struct definitions */
typedef struct _vscf_MessageGroupInfo {
    pb_byte_t session_id[32];
    uint32_t epoch;
    pb_byte_t key[32];
/* @@protoc_insertion_point(struct:vscf_MessageGroupInfo) */
} vscf_MessageGroupInfo;

typedef PB_BYTES_ARRAY_T(74) vscf_RegularGroupMessage_header_t;
typedef struct _vscf_RegularGroupMessage {
    vscf_RegularGroupMessage_header_t header;
    pb_byte_t signature[64];
    pb_bytes_array_t *cipher_text;
/* @@protoc_insertion_point(struct:vscf_RegularGroupMessage) */
} vscf_RegularGroupMessage;

typedef struct _vscf_RegularGroupMessageHeader {
    pb_byte_t session_id[32];
    uint32_t epoch;
    pb_byte_t salt[32];
/* @@protoc_insertion_point(struct:vscf_RegularGroupMessageHeader) */
} vscf_RegularGroupMessageHeader;

typedef struct _vscf_GroupMessage {
    uint32_t version;
    bool has_group_info;
    vscf_MessageGroupInfo group_info;
    bool has_regular_message;
    vscf_RegularGroupMessage regular_message;
/* @@protoc_insertion_point(struct:vscf_GroupMessage) */
} vscf_GroupMessage;

/* Default values for struct fields */

/* Initializer values for message structs */
#define vscf_MessageGroupInfo_init_default       {{0}, 0, {0}}
#define vscf_RegularGroupMessageHeader_init_default {{0}, 0, {0}}
#define vscf_RegularGroupMessage_init_default    {{0, {0}}, {0}, NULL}
#define vscf_GroupMessage_init_default           {0, false, vscf_MessageGroupInfo_init_default, false, vscf_RegularGroupMessage_init_default}
#define vscf_MessageGroupInfo_init_zero          {{0}, 0, {0}}
#define vscf_RegularGroupMessageHeader_init_zero {{0}, 0, {0}}
#define vscf_RegularGroupMessage_init_zero       {{0, {0}}, {0}, NULL}
#define vscf_GroupMessage_init_zero              {0, false, vscf_MessageGroupInfo_init_zero, false, vscf_RegularGroupMessage_init_zero}

/* Field tags (for use in manual encoding/decoding) */
#define vscf_MessageGroupInfo_session_id_tag     1
#define vscf_MessageGroupInfo_epoch_tag          2
#define vscf_MessageGroupInfo_key_tag            3
#define vscf_RegularGroupMessage_header_tag      1
#define vscf_RegularGroupMessage_signature_tag   2
#define vscf_RegularGroupMessage_cipher_text_tag 3
#define vscf_RegularGroupMessageHeader_session_id_tag 1
#define vscf_RegularGroupMessageHeader_epoch_tag 2
#define vscf_RegularGroupMessageHeader_salt_tag  3
#define vscf_GroupMessage_version_tag            1
#define vscf_GroupMessage_group_info_tag         2
#define vscf_GroupMessage_regular_message_tag    3

/* Struct field encoding specification for nanopb */
extern const pb_field_t vscf_MessageGroupInfo_fields[4];
extern const pb_field_t vscf_RegularGroupMessageHeader_fields[4];
extern const pb_field_t vscf_RegularGroupMessage_fields[4];
extern const pb_field_t vscf_GroupMessage_fields[4];

/* Maximum encoded size of messages (where known) */
#define vscf_MessageGroupInfo_size               74
#define vscf_RegularGroupMessageHeader_size      74
/* vscf_RegularGroupMessage_size depends on runtime parameters */
/* vscf_GroupMessage_size depends on runtime parameters */

/* Message IDs (where set with "msgid" option) */
#ifdef PB_MSGID

#define VSCF_GROUPMESSAGE_MESSAGES \


#endif

#ifdef __cplusplus
} /* extern "C" */
#endif
/* @@protoc_insertion_point(eof) */

#endif
