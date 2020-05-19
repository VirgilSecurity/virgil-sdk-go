/* Automatically generated nanopb header */
/* Generated by nanopb-0.3.9.4 at Tue May 19 07:42:49 2020. */

#ifndef PB_PHEMODELS_PB_H_INCLUDED
#define PB_PHEMODELS_PB_H_INCLUDED
#include <pb.h>

/* @@protoc_insertion_point(includes) */
#if PB_PROTO_HEADER_VERSION != 30
#error Regenerate this file with the current version of nanopb generator.
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Struct definitions */
typedef struct _EnrollmentRecord {
    pb_byte_t ns[32];
    pb_byte_t nc[32];
    pb_byte_t t0[65];
    pb_byte_t t1[65];
/* @@protoc_insertion_point(struct:EnrollmentRecord) */
} EnrollmentRecord;

typedef struct _ProofOfFail {
    pb_byte_t term1[65];
    pb_byte_t term2[65];
    pb_byte_t term3[65];
    pb_byte_t term4[65];
    pb_byte_t blind_a[32];
    pb_byte_t blind_b[32];
/* @@protoc_insertion_point(struct:ProofOfFail) */
} ProofOfFail;

typedef struct _ProofOfSuccess {
    pb_byte_t term1[65];
    pb_byte_t term2[65];
    pb_byte_t term3[65];
    pb_byte_t blind_x[32];
/* @@protoc_insertion_point(struct:ProofOfSuccess) */
} ProofOfSuccess;

typedef struct _UpdateToken {
    pb_byte_t a[32];
    pb_byte_t b[32];
/* @@protoc_insertion_point(struct:UpdateToken) */
} UpdateToken;

typedef struct _VerifyPasswordRequest {
    pb_byte_t ns[32];
    pb_byte_t c0[65];
/* @@protoc_insertion_point(struct:VerifyPasswordRequest) */
} VerifyPasswordRequest;

typedef struct _EnrollmentResponse {
    pb_byte_t ns[32];
    pb_byte_t c0[65];
    pb_byte_t c1[65];
    ProofOfSuccess proof;
/* @@protoc_insertion_point(struct:EnrollmentResponse) */
} EnrollmentResponse;

typedef struct _VerifyPasswordResponse {
    bool res;
    pb_byte_t c1[65];
    pb_size_t which_proof;
    union {
        ProofOfSuccess success;
        ProofOfFail fail;
    } proof;
/* @@protoc_insertion_point(struct:VerifyPasswordResponse) */
} VerifyPasswordResponse;

/* Default values for struct fields */

/* Initializer values for message structs */
#define EnrollmentRecord_init_default            {{0}, {0}, {0}, {0}}
#define ProofOfSuccess_init_default              {{0}, {0}, {0}, {0}}
#define ProofOfFail_init_default                 {{0}, {0}, {0}, {0}, {0}, {0}}
#define UpdateToken_init_default                 {{0}, {0}}
#define EnrollmentResponse_init_default          {{0}, {0}, {0}, ProofOfSuccess_init_default}
#define VerifyPasswordRequest_init_default       {{0}, {0}}
#define VerifyPasswordResponse_init_default      {0, {0}, 0, {ProofOfSuccess_init_default}}
#define EnrollmentRecord_init_zero               {{0}, {0}, {0}, {0}}
#define ProofOfSuccess_init_zero                 {{0}, {0}, {0}, {0}}
#define ProofOfFail_init_zero                    {{0}, {0}, {0}, {0}, {0}, {0}}
#define UpdateToken_init_zero                    {{0}, {0}}
#define EnrollmentResponse_init_zero             {{0}, {0}, {0}, ProofOfSuccess_init_zero}
#define VerifyPasswordRequest_init_zero          {{0}, {0}}
#define VerifyPasswordResponse_init_zero         {0, {0}, 0, {ProofOfSuccess_init_zero}}

/* Field tags (for use in manual encoding/decoding) */
#define EnrollmentRecord_ns_tag                  1
#define EnrollmentRecord_nc_tag                  2
#define EnrollmentRecord_t0_tag                  3
#define EnrollmentRecord_t1_tag                  4
#define ProofOfFail_term1_tag                    1
#define ProofOfFail_term2_tag                    2
#define ProofOfFail_term3_tag                    3
#define ProofOfFail_term4_tag                    4
#define ProofOfFail_blind_a_tag                  5
#define ProofOfFail_blind_b_tag                  6
#define ProofOfSuccess_term1_tag                 1
#define ProofOfSuccess_term2_tag                 2
#define ProofOfSuccess_term3_tag                 3
#define ProofOfSuccess_blind_x_tag               4
#define UpdateToken_a_tag                        1
#define UpdateToken_b_tag                        2
#define VerifyPasswordRequest_ns_tag             1
#define VerifyPasswordRequest_c0_tag             2
#define EnrollmentResponse_ns_tag                1
#define EnrollmentResponse_c0_tag                2
#define EnrollmentResponse_c1_tag                3
#define EnrollmentResponse_proof_tag             4
#define VerifyPasswordResponse_success_tag       3
#define VerifyPasswordResponse_fail_tag          4
#define VerifyPasswordResponse_res_tag           1
#define VerifyPasswordResponse_c1_tag            2

/* Struct field encoding specification for nanopb */
extern const pb_field_t EnrollmentRecord_fields[5];
extern const pb_field_t ProofOfSuccess_fields[5];
extern const pb_field_t ProofOfFail_fields[7];
extern const pb_field_t UpdateToken_fields[3];
extern const pb_field_t EnrollmentResponse_fields[5];
extern const pb_field_t VerifyPasswordRequest_fields[3];
extern const pb_field_t VerifyPasswordResponse_fields[5];

/* Maximum encoded size of messages (where known) */
#define EnrollmentRecord_size                    202
#define ProofOfSuccess_size                      235
#define ProofOfFail_size                         336
#define UpdateToken_size                         68
#define EnrollmentResponse_size                  406
#define VerifyPasswordRequest_size               101
#define VerifyPasswordResponse_size              408

/* Message IDs (where set with "msgid" option) */
#ifdef PB_MSGID

#define PHEMODELS_MESSAGES \


#endif

#ifdef __cplusplus
} /* extern "C" */
#endif
/* @@protoc_insertion_point(eof) */

#endif
