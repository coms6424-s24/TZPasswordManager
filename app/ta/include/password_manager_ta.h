/*
 * Copyright (c) 2016-2017, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef TA_PASSWORD_MANAGER_H
#define TA_PASSWORD_MANAGER_H

/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define TA_PASSWORD_MANAGER_UUID \
    { 0xae49df22, 0x409b, 0x46f1, \
        { 0xb6, 0xef, 0x68, 0x8f, 0x54, 0x83, 0x6c, 0x3c } }

/* The function IDs implemented in this TA */
#define TA_PASSWORD_MANAGER_CMD_CREATE_ARCHIVE  0
#define TA_PASSWORD_MANAGER_CMD_RESTORE_ARCHIVE 1
#define TA_PASSWORD_MANAGER_CMD_ADD_ENTRY       2
#define TA_PASSWORD_MANAGER_CMD_GET_ENTRY       3
#define TA_PASSWORD_MANAGER_CMD_DEL_ENTRY       4
#define TA_PASSWORD_MANAGER_CMD_UPDATE_ENTRY    5

#define RECOVERY_KEY_LEN 32
#define SHA256_DIGEST_LENGTH 32
#define MAX_PWD_LEN      64
#define MAX_SITE_URL_LEN 128
#define MAX_SITE_NAME_LEN 64
#define MAX_ARCHIVE_NAME_LEN 64
#define MAX_USERNAME_LEN 64

#define AES256_KEY_SIZE 32
#define SALT_SIZE 16

struct pwd_entry
{
    char site_url[MAX_SITE_URL_LEN];
    char site_name[MAX_SITE_NAME_LEN];
    char username[MAX_USERNAME_LEN];
    char password[MAX_PWD_LEN];
};

struct archive_entry
{
    char hash[SHA256_DIGEST_LENGTH];
    char salt[SALT_SIZE];
    struct pwd_entry entry;
};


#endif /*TA_PASSWORD_MANAGER_H*/
