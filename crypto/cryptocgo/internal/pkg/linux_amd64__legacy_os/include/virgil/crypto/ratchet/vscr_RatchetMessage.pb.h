/* Automatically generated nanopb header */
/* Generated by nanopb-0.3.9.4 at Wed Dec  4 12:40:29 2019. */

#ifndef PB_VSCR_RATCHETMESSAGE_PB_H_INCLUDED
#define PB_VSCR_RATCHETMESSAGE_PB_H_INCLUDED
#include <pb.h>

/* @@protoc_insertion_point(includes) */
#if PB_PROTO_HEADER_VERSION != 30
#error Regenerate this file with the current version of nanopb generator.
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Struct definitions */
typedef struct _vscr_PrekeyMessage {
    pb_byte_t sender_identity_key[32];
    pb_byte_t sender_ephemeral_key[32];
    pb_byte_t receiver_long_term_key[32];
    bool has_receiver_one_time_key;
    pb_byte_t receiver_one_time_key[32];
/* @@protoc_insertion_point(struct:vscr_PrekeyMessage) */
} vscr_PrekeyMessage;

typedef PB_BYTES_ARRAY_T(52) vscr_RegularMessage_header_t;
typedef struct _vscr_RegularMessage {
    vscr_RegularMessage_header_t header;
    pb_bytes_array_t *cipher_text;
/* @@protoc_insertion_point(struct:vscr_RegularMessage) */
} vscr_RegularMessage;

typedef struct _vscr_RegularMessageHeader {
    uint32_t counter;
    uint32_t prev_chain_count;
    pb_byte_t public_key[32];
/* @@protoc_insertion_point(struct:vscr_RegularMessageHeader) */
} vscr_RegularMessageHeader;

typedef struct _vscr_Message {
    uint32_t version;
    vscr_RegularMessage regular_message;
    bool has_prekey_message;
    vscr_PrekeyMessage prekey_message;
/* @@protoc_insertion_point(struct:vscr_Message) */
} vscr_Message;

/* Default values for struct fields */

/* Initializer values for message structs */
#define vscr_RegularMessageHeader_init_default   {0, 0, {0}}
#define vscr_RegularMessage_init_default         {{0, {0}}, NULL}
#define vscr_PrekeyMessage_init_default          {{0}, {0}, {0}, false, {0}}
#define vscr_Message_init_default                {0, vscr_RegularMessage_init_default, false, vscr_PrekeyMessage_init_default}
#define vscr_RegularMessageHeader_init_zero      {0, 0, {0}}
#define vscr_RegularMessage_init_zero            {{0, {0}}, NULL}
#define vscr_PrekeyMessage_init_zero             {{0}, {0}, {0}, false, {0}}
#define vscr_Message_init_zero                   {0, vscr_RegularMessage_init_zero, false, vscr_PrekeyMessage_init_zero}

/* Field tags (for use in manual encoding/decoding) */
#define vscr_PrekeyMessage_sender_identity_key_tag 1
#define vscr_PrekeyMessage_sender_ephemeral_key_tag 2
#define vscr_PrekeyMessage_receiver_long_term_key_tag 3
#define vscr_PrekeyMessage_receiver_one_time_key_tag 4
#define vscr_RegularMessage_header_tag           1
#define vscr_RegularMessage_cipher_text_tag      2
#define vscr_RegularMessageHeader_counter_tag    1
#define vscr_RegularMessageHeader_prev_chain_count_tag 2
#define vscr_RegularMessageHeader_public_key_tag 3
#define vscr_Message_version_tag                 1
#define vscr_Message_regular_message_tag         2
#define vscr_Message_prekey_message_tag          3

/* Struct field encoding specification for nanopb */
extern const pb_field_t vscr_RegularMessageHeader_fields[4];
extern const pb_field_t vscr_RegularMessage_fields[3];
extern const pb_field_t vscr_PrekeyMessage_fields[5];
extern const pb_field_t vscr_Message_fields[4];

/* Maximum encoded size of messages (where known) */
#define vscr_RegularMessageHeader_size           46
/* vscr_RegularMessage_size depends on runtime parameters */
#define vscr_PrekeyMessage_size                  136
/* vscr_Message_size depends on runtime parameters */

/* Message IDs (where set with "msgid" option) */
#ifdef PB_MSGID

#define VSCR_RATCHETMESSAGE_MESSAGES \


#endif

#ifdef __cplusplus
} /* extern "C" */
#endif
/* @@protoc_insertion_point(eof) */

#endif
