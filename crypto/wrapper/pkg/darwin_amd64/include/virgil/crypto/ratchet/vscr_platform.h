//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2019 Virgil Security, Inc.
//
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are
//  met:
//
//      (1) Redistributions of source code must retain the above copyright
//      notice, this list of conditions and the following disclaimer.
//
//      (2) Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the following disclaimer in
//      the documentation and/or other materials provided with the
//      distribution.
//
//      (3) Neither the name of the copyright holder nor the names of its
//      contributors may be used to endorse or promote products derived from
//      this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
//  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
//  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
//  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
//  IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
//  POSSIBILITY OF SUCH DAMAGE.
//
//  Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
// --------------------------------------------------------------------------
// clang-format off


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------


//  @description
// --------------------------------------------------------------------------
//  This file contains platform specific information that is known during compilation.
// --------------------------------------------------------------------------

#ifndef VSCR_PLATFORM_H_INCLUDED
#define VSCR_PLATFORM_H_INCLUDED

// clang-format on
//  @end


#ifdef __cplusplus
extern "C" {
#endif


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

#define VSCR_HAVE_ASSERT_H 1
#if VSCR_HAVE_ASSERT_H
#   include <assert.h>
#endif

#define VSCR_HAVE_STDATOMIC_H 1
#if VSCR_HAVE_STDATOMIC_H
#   include <stdatomic.h>
#endif

#ifndef VSCR_SHARED_LIBRARY
#define VSCR_SHARED_LIBRARY 0
#endif

#ifndef VSCR_MULTI_THREADING
#define VSCR_MULTI_THREADING 1
#endif

#ifndef VSCR_RATCHET_COMMON
#define VSCR_RATCHET_COMMON 1
#endif

#ifndef VSCR_RATCHET_COMMON_HIDDEN
#define VSCR_RATCHET_COMMON_HIDDEN 1
#endif

#ifndef VSCR_RATCHET_KEY_UTILS
#define VSCR_RATCHET_KEY_UTILS 1
#endif

#ifndef VSCR_RATCHET_KEY_ID
#define VSCR_RATCHET_KEY_ID 1
#endif

#ifndef VSCR_ERROR
#define VSCR_ERROR 1
#endif

#ifndef VSCR_RATCHET_X3DH
#define VSCR_RATCHET_X3DH 1
#endif

#ifndef VSCR_RATCHET_MESSAGE
#define VSCR_RATCHET_MESSAGE 1
#endif

#ifndef VSCR_RATCHET_CIPHER
#define VSCR_RATCHET_CIPHER 1
#endif

#ifndef VSCR_RATCHET_CHAIN_KEY
#define VSCR_RATCHET_CHAIN_KEY 1
#endif

#ifndef VSCR_RATCHET_MESSAGE_KEY
#define VSCR_RATCHET_MESSAGE_KEY 1
#endif

#ifndef VSCR_RATCHET_MESSAGE_KEY_NODE
#define VSCR_RATCHET_MESSAGE_KEY_NODE 1
#endif

#ifndef VSCR_RATCHET_SKIPPED_MESSAGES_ROOT_NODE
#define VSCR_RATCHET_SKIPPED_MESSAGES_ROOT_NODE 1
#endif

#ifndef VSCR_RATCHET_SKIPPED_MESSAGES
#define VSCR_RATCHET_SKIPPED_MESSAGES 1
#endif

#ifndef VSCR_RATCHET_RECEIVER_CHAIN
#define VSCR_RATCHET_RECEIVER_CHAIN 1
#endif

#ifndef VSCR_RATCHET_SENDER_CHAIN
#define VSCR_RATCHET_SENDER_CHAIN 1
#endif

#ifndef VSCR_RATCHET_KEYS
#define VSCR_RATCHET_KEYS 1
#endif

#ifndef VSCR_RATCHET
#define VSCR_RATCHET 1
#endif

#ifndef VSCR_RATCHET_SESSION
#define VSCR_RATCHET_SESSION 1
#endif

#ifndef VSCR_RATCHET_GROUP_PARTICIPANT_EPOCH
#define VSCR_RATCHET_GROUP_PARTICIPANT_EPOCH 1
#endif

#ifndef VSCR_RATCHET_GROUP_PARTICIPANT_INFO
#define VSCR_RATCHET_GROUP_PARTICIPANT_INFO 1
#endif

#ifndef VSCR_RATCHET_GROUP_PARTICIPANTS_INFO
#define VSCR_RATCHET_GROUP_PARTICIPANTS_INFO 1
#endif

#ifndef VSCR_RATCHET_GROUP_PARTICIPANT
#define VSCR_RATCHET_GROUP_PARTICIPANT 1
#endif

#ifndef VSCR_RATCHET_GROUP_MESSAGE
#define VSCR_RATCHET_GROUP_MESSAGE 1
#endif

#ifndef VSCR_RATCHET_GROUP_TICKET
#define VSCR_RATCHET_GROUP_TICKET 1
#endif

#ifndef VSCR_RATCHET_GROUP_PARTICIPANTS_IDS
#define VSCR_RATCHET_GROUP_PARTICIPANTS_IDS 1
#endif

#ifndef VSCR_RATCHET_GROUP_SESSION
#define VSCR_RATCHET_GROUP_SESSION 1
#endif

//
//  Defines namespace include prefix for project 'common'.
//
#if !defined(VSCR_INTERNAL_BUILD)
#define VSCR_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK 0
#else
#define VSCR_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK 0
#endif

//
//  Defines namespace include prefix for project 'foundation'.
//
#if !defined(VSCR_INTERNAL_BUILD)
#define VSCR_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK 0
#else
#define VSCR_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK 0
#endif


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCR_PLATFORM_H_INCLUDED
//  @end
