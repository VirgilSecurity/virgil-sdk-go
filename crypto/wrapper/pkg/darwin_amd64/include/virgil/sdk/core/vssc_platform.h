//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2020 Virgil Security, Inc.
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

#ifndef VSSC_PLATFORM_H_INCLUDED
#define VSSC_PLATFORM_H_INCLUDED

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

#ifndef VSSC_HAVE_ASSERT_H
#define VSSC_HAVE_ASSERT_H 1
#endif

#ifndef VSSC_HAVE_STDATOMIC_H
#define VSSC_HAVE_STDATOMIC_H 1
#endif

#ifndef VSSC_SHARED_LIBRARY
#define VSSC_SHARED_LIBRARY 0
#endif

#ifndef VSSC_MULTI_THREADING
#define VSSC_MULTI_THREADING 1
#endif

#ifndef VSSC_USE_DEFAULT_HTTP_CLIENT
#define VSSC_USE_DEFAULT_HTTP_CLIENT 1
#endif

#ifndef VSSC_HTTP_CLIENT
#define VSSC_HTTP_CLIENT 1
#endif

#ifndef VSSC_HTTP_CLIENT_CURL
#define VSSC_HTTP_CLIENT_CURL 1
#endif

#ifndef VSSC_HTTP_CLIENT_X
#define VSSC_HTTP_CLIENT_X 0
#endif

#ifndef VSSC_ERROR
#define VSSC_ERROR 1
#endif

#ifndef VSSC_ERROR_MESSAGE
#define VSSC_ERROR_MESSAGE 1
#endif

#ifndef VSSC_JSON_OBJECT
#define VSSC_JSON_OBJECT 1
#endif

#ifndef VSSC_JSON_ARRAY
#define VSSC_JSON_ARRAY 1
#endif

#ifndef VSSC_UNIX_TIME
#define VSSC_UNIX_TIME 1
#endif

#ifndef VSSC_STRING_LIST
#define VSSC_STRING_LIST 1
#endif

#ifndef VSSC_NUMBER_LIST
#define VSSC_NUMBER_LIST 1
#endif

#ifndef VSSC_STRING_MAP
#define VSSC_STRING_MAP 1
#endif

#ifndef VSSC_STRING_MAP_BUCKET
#define VSSC_STRING_MAP_BUCKET 1
#endif

#ifndef VSSC_BASE64_URL
#define VSSC_BASE64_URL 1
#endif

#ifndef VSSC_JWT
#define VSSC_JWT 1
#endif

#ifndef VSSC_JWT_HEADER
#define VSSC_JWT_HEADER 1
#endif

#ifndef VSSC_JWT_PAYLOAD
#define VSSC_JWT_PAYLOAD 1
#endif

#ifndef VSSC_JWT_GENERATOR
#define VSSC_JWT_GENERATOR 1
#endif

#ifndef VSSC_HTTP_HEADER
#define VSSC_HTTP_HEADER 1
#endif

#ifndef VSSC_HTTP_HEADER_LIST
#define VSSC_HTTP_HEADER_LIST 1
#endif

#ifndef VSSC_HTTP_REQUEST
#define VSSC_HTTP_REQUEST 1
#endif

#ifndef VSSC_HTTP_RESPONSE
#define VSSC_HTTP_RESPONSE 1
#endif

#ifndef VSSC_VIRGIL_HTTP_CLIENT
#define VSSC_VIRGIL_HTTP_CLIENT 1
#endif

#ifndef VSSC_VIRGIL_HTTP_CLIENT_DEBUG
#define VSSC_VIRGIL_HTTP_CLIENT_DEBUG 0
#endif

#ifndef VSSC_KEY_HANDLER
#define VSSC_KEY_HANDLER 1
#endif

#ifndef VSSC_KEY_HANDLER_LIST
#define VSSC_KEY_HANDLER_LIST 1
#endif

#ifndef VSSC_CARD_CLIENT
#define VSSC_CARD_CLIENT 1
#endif

#ifndef VSSC_RAW_CARD
#define VSSC_RAW_CARD 1
#endif

#ifndef VSSC_RAW_CARD_LIST
#define VSSC_RAW_CARD_LIST 1
#endif

#ifndef VSSC_RAW_CARD_SIGNER
#define VSSC_RAW_CARD_SIGNER 1
#endif

#ifndef VSSC_RAW_CARD_VERIFIER
#define VSSC_RAW_CARD_VERIFIER 1
#endif

#ifndef VSSC_RAW_CARD_SIGNATURE
#define VSSC_RAW_CARD_SIGNATURE 1
#endif

#ifndef VSSC_RAW_CARD_SIGNATURE_LIST
#define VSSC_RAW_CARD_SIGNATURE_LIST 1
#endif

#ifndef VSSC_CARD
#define VSSC_CARD 1
#endif

#ifndef VSSC_CARD_LIST
#define VSSC_CARD_LIST 1
#endif

#ifndef VSSC_CARD_MANAGER
#define VSSC_CARD_MANAGER 1
#endif

//
//  Defines namespace include prefix for project 'common'.
//
#if !defined(VSSC_INTERNAL_BUILD)
#define VSSC_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK 0
#else
#define VSSC_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK 0
#endif

//
//  Defines namespace include prefix for project 'foundation'.
//
#if !defined(VSSC_INTERNAL_BUILD)
#define VSSC_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK 0
#else
#define VSSC_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK 0
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
#endif // VSSC_PLATFORM_H_INCLUDED
//  @end
