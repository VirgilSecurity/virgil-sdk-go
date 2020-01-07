/* Automatically generated nanopb header */
/* Generated by nanopb-0.3.9.4 at Mon Dec 30 08:40:06 2019. */

#ifndef PB_VSCR_RATCHETSESSION_PB_H_INCLUDED
#define PB_VSCR_RATCHETSESSION_PB_H_INCLUDED
#include <pb.h>

/* @@protoc_insertion_point(includes) */
#if PB_PROTO_HEADER_VERSION != 30
#error Regenerate this file with the current version of nanopb generator.
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Struct definitions */
typedef struct _vscr_ChainKey {
    uint32_t index;
    pb_byte_t key[32];
/* @@protoc_insertion_point(struct:vscr_ChainKey) */
} vscr_ChainKey;

typedef struct _vscr_MessageKey {
    uint32_t index;
    pb_byte_t key[32];
/* @@protoc_insertion_point(struct:vscr_MessageKey) */
} vscr_MessageKey;

typedef struct _vscr_SkippedMessageKey {
    pb_byte_t public_key[32];
    pb_size_t message_keys_count;
    struct _vscr_MessageKey *message_keys;
/* @@protoc_insertion_point(struct:vscr_SkippedMessageKey) */
} vscr_SkippedMessageKey;

typedef struct _vscr_GroupSession {
    uint32_t version;
    uint32_t my_epoch;
    vscr_ChainKey my_chain_key;
    uint32_t messages_count[4];
    pb_byte_t session_id[32];
    pb_byte_t my_id[32];
    pb_size_t participants_count;
    struct _vscr_ParticipantData *participants;
/* @@protoc_insertion_point(struct:vscr_GroupSession) */
} vscr_GroupSession;

typedef struct _vscr_ParticipantEpoch {
    uint32_t epoch;
    bool is_empty;
    bool has_chain_key;
    vscr_ChainKey chain_key;
    pb_size_t message_keys_count;
    struct _vscr_MessageKey *message_keys;
/* @@protoc_insertion_point(struct:vscr_ParticipantEpoch) */
} vscr_ParticipantEpoch;

typedef struct _vscr_ReceiverChain {
    pb_byte_t public_key[32];
    vscr_ChainKey chain_key;
/* @@protoc_insertion_point(struct:vscr_ReceiverChain) */
} vscr_ReceiverChain;

typedef struct _vscr_SenderChain {
    pb_byte_t private_key[32];
    pb_byte_t public_key[32];
    vscr_ChainKey chain_key;
/* @@protoc_insertion_point(struct:vscr_SenderChain) */
} vscr_SenderChain;

typedef struct _vscr_SkippedMessages {
    pb_size_t keys_count;
    vscr_SkippedMessageKey keys[5];
/* @@protoc_insertion_point(struct:vscr_SkippedMessages) */
} vscr_SkippedMessages;

typedef struct _vscr_ParticipantData {
    pb_byte_t id[32];
    pb_byte_t pub_key[32];
    vscr_ParticipantEpoch epochs[5];
/* @@protoc_insertion_point(struct:vscr_ParticipantData) */
} vscr_ParticipantData;

typedef struct _vscr_Ratchet {
    bool has_sender_chain;
    vscr_SenderChain sender_chain;
    uint32_t prev_sender_chain_count;
    bool has_receiver_chain;
    vscr_ReceiverChain receiver_chain;
    pb_byte_t root_key[32];
    vscr_SkippedMessages skipped_messages;
/* @@protoc_insertion_point(struct:vscr_Ratchet) */
} vscr_Ratchet;

typedef struct _vscr_Session {
    uint32_t version;
    bool received_first_response;
    bool is_initiator;
    pb_byte_t sender_identity_key[32];
    pb_byte_t sender_ephemeral_key[32];
    pb_byte_t receiver_long_term_key[32];
    bool has_receiver_one_time_key;
    pb_byte_t receiver_one_time_key[32];
    vscr_Ratchet ratchet;
/* @@protoc_insertion_point(struct:vscr_Session) */
} vscr_Session;

/* Default values for struct fields */

/* Initializer values for message structs */
#define vscr_ChainKey_init_default               {0, {0}}
#define vscr_MessageKey_init_default             {0, {0}}
#define vscr_SenderChain_init_default            {{0}, {0}, vscr_ChainKey_init_default}
#define vscr_ReceiverChain_init_default          {{0}, vscr_ChainKey_init_default}
#define vscr_SkippedMessageKey_init_default      {{0}, 0, NULL}
#define vscr_SkippedMessages_init_default        {0, {vscr_SkippedMessageKey_init_default, vscr_SkippedMessageKey_init_default, vscr_SkippedMessageKey_init_default, vscr_SkippedMessageKey_init_default, vscr_SkippedMessageKey_init_default}}
#define vscr_Ratchet_init_default                {false, vscr_SenderChain_init_default, 0, false, vscr_ReceiverChain_init_default, {0}, vscr_SkippedMessages_init_default}
#define vscr_Session_init_default                {0, 0, 0, {0}, {0}, {0}, false, {0}, vscr_Ratchet_init_default}
#define vscr_ParticipantEpoch_init_default       {0, 0, false, vscr_ChainKey_init_default, 0, NULL}
#define vscr_ParticipantData_init_default        {{0}, {0}, {vscr_ParticipantEpoch_init_default, vscr_ParticipantEpoch_init_default, vscr_ParticipantEpoch_init_default, vscr_ParticipantEpoch_init_default, vscr_ParticipantEpoch_init_default}}
#define vscr_GroupSession_init_default           {0, 0, vscr_ChainKey_init_default, {0, 0, 0, 0}, {0}, {0}, 0, NULL}
#define vscr_ChainKey_init_zero                  {0, {0}}
#define vscr_MessageKey_init_zero                {0, {0}}
#define vscr_SenderChain_init_zero               {{0}, {0}, vscr_ChainKey_init_zero}
#define vscr_ReceiverChain_init_zero             {{0}, vscr_ChainKey_init_zero}
#define vscr_SkippedMessageKey_init_zero         {{0}, 0, NULL}
#define vscr_SkippedMessages_init_zero           {0, {vscr_SkippedMessageKey_init_zero, vscr_SkippedMessageKey_init_zero, vscr_SkippedMessageKey_init_zero, vscr_SkippedMessageKey_init_zero, vscr_SkippedMessageKey_init_zero}}
#define vscr_Ratchet_init_zero                   {false, vscr_SenderChain_init_zero, 0, false, vscr_ReceiverChain_init_zero, {0}, vscr_SkippedMessages_init_zero}
#define vscr_Session_init_zero                   {0, 0, 0, {0}, {0}, {0}, false, {0}, vscr_Ratchet_init_zero}
#define vscr_ParticipantEpoch_init_zero          {0, 0, false, vscr_ChainKey_init_zero, 0, NULL}
#define vscr_ParticipantData_init_zero           {{0}, {0}, {vscr_ParticipantEpoch_init_zero, vscr_ParticipantEpoch_init_zero, vscr_ParticipantEpoch_init_zero, vscr_ParticipantEpoch_init_zero, vscr_ParticipantEpoch_init_zero}}
#define vscr_GroupSession_init_zero              {0, 0, vscr_ChainKey_init_zero, {0, 0, 0, 0}, {0}, {0}, 0, NULL}

/* Field tags (for use in manual encoding/decoding) */
#define vscr_ChainKey_index_tag                  1
#define vscr_ChainKey_key_tag                    2
#define vscr_MessageKey_index_tag                1
#define vscr_MessageKey_key_tag                  2
#define vscr_SkippedMessageKey_public_key_tag    1
#define vscr_SkippedMessageKey_message_keys_tag  2
#define vscr_GroupSession_version_tag            1
#define vscr_GroupSession_my_epoch_tag           2
#define vscr_GroupSession_my_chain_key_tag       3
#define vscr_GroupSession_messages_count_tag     4
#define vscr_GroupSession_session_id_tag         5
#define vscr_GroupSession_my_id_tag              6
#define vscr_GroupSession_participants_tag       7
#define vscr_ParticipantEpoch_epoch_tag          1
#define vscr_ParticipantEpoch_is_empty_tag       2
#define vscr_ParticipantEpoch_chain_key_tag      3
#define vscr_ParticipantEpoch_message_keys_tag   4
#define vscr_ReceiverChain_public_key_tag        1
#define vscr_ReceiverChain_chain_key_tag         2
#define vscr_SenderChain_private_key_tag         1
#define vscr_SenderChain_public_key_tag          2
#define vscr_SenderChain_chain_key_tag           3
#define vscr_SkippedMessages_keys_tag            1
#define vscr_ParticipantData_id_tag              1
#define vscr_ParticipantData_pub_key_tag         2
#define vscr_ParticipantData_epochs_tag          3
#define vscr_Ratchet_sender_chain_tag            1
#define vscr_Ratchet_prev_sender_chain_count_tag 2
#define vscr_Ratchet_receiver_chain_tag          3
#define vscr_Ratchet_root_key_tag                4
#define vscr_Ratchet_skipped_messages_tag        5
#define vscr_Session_version_tag                 1
#define vscr_Session_received_first_response_tag 2
#define vscr_Session_is_initiator_tag            3
#define vscr_Session_sender_identity_key_tag     4
#define vscr_Session_sender_ephemeral_key_tag    5
#define vscr_Session_receiver_long_term_key_tag  6
#define vscr_Session_receiver_one_time_key_tag   7
#define vscr_Session_ratchet_tag                 8

/* Struct field encoding specification for nanopb */
extern const pb_field_t vscr_ChainKey_fields[3];
extern const pb_field_t vscr_MessageKey_fields[3];
extern const pb_field_t vscr_SenderChain_fields[4];
extern const pb_field_t vscr_ReceiverChain_fields[3];
extern const pb_field_t vscr_SkippedMessageKey_fields[3];
extern const pb_field_t vscr_SkippedMessages_fields[2];
extern const pb_field_t vscr_Ratchet_fields[6];
extern const pb_field_t vscr_Session_fields[9];
extern const pb_field_t vscr_ParticipantEpoch_fields[5];
extern const pb_field_t vscr_ParticipantData_fields[4];
extern const pb_field_t vscr_GroupSession_fields[8];

/* Maximum encoded size of messages (where known) */
#define vscr_ChainKey_size                       40
#define vscr_MessageKey_size                     40
#define vscr_SenderChain_size                    110
#define vscr_ReceiverChain_size                  76
/* vscr_SkippedMessageKey_size depends on runtime parameters */
/* vscr_SkippedMessages_size depends on runtime parameters */
/* vscr_Ratchet_size depends on runtime parameters */
/* vscr_Session_size depends on runtime parameters */
/* vscr_ParticipantEpoch_size depends on runtime parameters */
/* vscr_ParticipantData_size depends on runtime parameters */
/* vscr_GroupSession_size depends on runtime parameters */

/* Message IDs (where set with "msgid" option) */
#ifdef PB_MSGID

#define VSCR_RATCHETSESSION_MESSAGES \


#endif

#ifdef __cplusplus
} /* extern "C" */
#endif
/* @@protoc_insertion_point(eof) */

#endif
