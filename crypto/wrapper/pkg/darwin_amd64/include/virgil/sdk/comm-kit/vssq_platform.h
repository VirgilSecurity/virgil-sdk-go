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

#ifndef VSSQ_PLATFORM_H_INCLUDED
#define VSSQ_PLATFORM_H_INCLUDED

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

#ifndef VSSQ_HAVE_ASSERT_H
#define VSSQ_HAVE_ASSERT_H 1
#endif

#ifndef VSSQ_HAVE_STDATOMIC_H
#define VSSQ_HAVE_STDATOMIC_H 1
#endif

#ifndef VSSQ_SHARED_LIBRARY
#define VSSQ_SHARED_LIBRARY 0
#endif

#ifndef VSSQ_MULTI_THREADING
#define VSSQ_MULTI_THREADING 1
#endif

#ifndef VSSQ_ERROR
#define VSSQ_ERROR 1
#endif

#ifndef VSSQ_ERROR_MESSAGE
#define VSSQ_ERROR_MESSAGE 1
#endif

#ifndef VSSQ_EJABBERD_JWT
#define VSSQ_EJABBERD_JWT 1
#endif

#ifndef VSSQ_MESSENGER
#define VSSQ_MESSENGER 1
#endif

#ifndef VSSQ_MESSENGER_AUTH
#define VSSQ_MESSENGER_AUTH 1
#endif

#ifndef VSSQ_MESSENGER_CREDS
#define VSSQ_MESSENGER_CREDS 1
#endif

#ifndef VSSQ_MESSENGER_CONFIG
#define VSSQ_MESSENGER_CONFIG 1
#endif

#ifndef VSSQ_MESSENGER_CONTACTS
#define VSSQ_MESSENGER_CONTACTS 1
#endif

#ifndef VSSQ_MESSENGER_USER
#define VSSQ_MESSENGER_USER 1
#endif

#ifndef VSSQ_MESSENGER_USER_LIST
#define VSSQ_MESSENGER_USER_LIST 1
#endif

#ifndef VSSQ_MESSENGER_GROUP
#define VSSQ_MESSENGER_GROUP 1
#endif

#ifndef VSSQ_MESSENGER_GROUP_EPOCH
#define VSSQ_MESSENGER_GROUP_EPOCH 1
#endif

#ifndef VSSQ_MESSENGER_GROUP_EPOCH_LIST
#define VSSQ_MESSENGER_GROUP_EPOCH_LIST 1
#endif

#ifndef VSSQ_MESSENGER_GROUP_EPOCH_KEYKNOX_STORAGE
#define VSSQ_MESSENGER_GROUP_EPOCH_KEYKNOX_STORAGE 1
#endif

#ifndef VSSQ_MESSENGER_FILE_CIPHER
#define VSSQ_MESSENGER_FILE_CIPHER 1
#endif

#ifndef VSSQ_MESSENGER_CLOUD_FS
#define VSSQ_MESSENGER_CLOUD_FS 1
#endif

#ifndef VSSQ_MESSENGER_CLOUD_FS_CLIENT
#define VSSQ_MESSENGER_CLOUD_FS_CLIENT 1
#endif

#ifndef VSSQ_MESSENGER_CLOUD_FS_CREATED_FILE
#define VSSQ_MESSENGER_CLOUD_FS_CREATED_FILE 1
#endif

#ifndef VSSQ_MESSENGER_CLOUD_FS_FOLDER
#define VSSQ_MESSENGER_CLOUD_FS_FOLDER 1
#endif

#ifndef VSSQ_MESSENGER_CLOUD_FS_FOLDER_INFO
#define VSSQ_MESSENGER_CLOUD_FS_FOLDER_INFO 1
#endif

#ifndef VSSQ_MESSENGER_CLOUD_FS_FOLDER_INFO_LIST
#define VSSQ_MESSENGER_CLOUD_FS_FOLDER_INFO_LIST 1
#endif

#ifndef VSSQ_MESSENGER_CLOUD_FS_FILE_INFO
#define VSSQ_MESSENGER_CLOUD_FS_FILE_INFO 1
#endif

#ifndef VSSQ_MESSENGER_CLOUD_FS_FILE_INFO_LIST
#define VSSQ_MESSENGER_CLOUD_FS_FILE_INFO_LIST 1
#endif

#ifndef VSSQ_MESSENGER_CLOUD_FS_FILE_DOWNLOAD_INFO
#define VSSQ_MESSENGER_CLOUD_FS_FILE_DOWNLOAD_INFO 1
#endif

#ifndef VSSQ_MESSENGER_CLOUD_FS_CIPHER
#define VSSQ_MESSENGER_CLOUD_FS_CIPHER 1
#endif

#ifndef VSSQ_MESSENGER_CLOUD_FS_ACCESS
#define VSSQ_MESSENGER_CLOUD_FS_ACCESS 1
#endif

#ifndef VSSQ_MESSENGER_CLOUD_FS_ACCESS_LIST
#define VSSQ_MESSENGER_CLOUD_FS_ACCESS_LIST 1
#endif

#ifndef VSSQ_CLOUD_FILE_SYSTEM_PB
#define VSSQ_CLOUD_FILE_SYSTEM_PB 1
#endif

#ifndef VSSQ_CONTACT_UTILS
#define VSSQ_CONTACT_UTILS 1
#endif

//
//  Defines namespace include prefix for project 'common'.
//
#if !defined(VSSQ_INTERNAL_BUILD)
#define VSSQ_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK 0
#else
#define VSSQ_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK 0
#endif

//
//  Defines namespace include prefix for project 'foundation'.
//
#if !defined(VSSQ_INTERNAL_BUILD)
#define VSSQ_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK 0
#else
#define VSSQ_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK 0
#endif

//
//  Defines namespace include prefix for project 'core sdk'.
//
#if !defined(VSSQ_INTERNAL_BUILD)
#define VSSQ_IMPORT_PROJECT_CORE_SDK_FROM_FRAMEWORK 0
#else
#define VSSQ_IMPORT_PROJECT_CORE_SDK_FROM_FRAMEWORK 0
#endif

//
//  Defines namespace include prefix for project 'brainkey sdk'.
//
#if !defined(VSSQ_INTERNAL_BUILD)
#define VSSQ_IMPORT_PROJECT_BRAINKEY_SDK_FROM_FRAMEWORK 0
#else
#define VSSQ_IMPORT_PROJECT_BRAINKEY_SDK_FROM_FRAMEWORK 0
#endif

//
//  Defines namespace include prefix for project 'keyknox sdk'.
//
#if !defined(VSSQ_INTERNAL_BUILD)
#define VSSQ_IMPORT_PROJECT_KEYKNOX_SDK_FROM_FRAMEWORK 0
#else
#define VSSQ_IMPORT_PROJECT_KEYKNOX_SDK_FROM_FRAMEWORK 0
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
#endif // VSSQ_PLATFORM_H_INCLUDED
//  @end
