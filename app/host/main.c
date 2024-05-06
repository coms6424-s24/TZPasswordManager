/*
 * Copyright (c) 2016, Linaro Limited
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

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

// Custom header file
#include "password_manager.h"

/* For the UUID (found in the TA's h-file(s)) */
#include "../ta/include/password_manager_ta.h"

// utils.c
void prepare_tee_session(struct tee_ctx *ctx);
void terminate_tee_session(struct tee_ctx *ctx);
void simple_hash(const uint8_t *data, size_t data_len, uint8_t *out_hash);

// ui.c
int main_choice_ui();
int open_archive_choice_ui(char *archive_name, char *password);
int add_entry_ui(struct pwd_entry *entry);
int get_entry_ui(char *site_name);
int create_archive_ui(char *archive_name, char *password);
int delete_archive_ui(char *archive_name, char *password);
int delete_entry_ui(char *site_name);

char *app_dir;

int create_archive(struct tee_ctx *tee_ctx)
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;

	// actual pwd managger calls
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_MEMREF_TEMP_INPUT, TEEC_NONE);

	// prepare buffers for password and for recovery key

	char password[MAX_PWD_LEN] = {0};
	char recovery_key[RECOVERY_KEY_LEN] = {0};
	char archive_name[MAX_ARCHIVE_NAME_LEN] = {0};

	if(create_archive_ui(archive_name, password) != 0)
	{
		printf("Error creating the archive.\n");
		return 1;
	}

	memset(password, 0, sizeof(password));
	memset(recovery_key, 0, sizeof(recovery_key));

	op.params[0].tmpref.buffer = password;
	op.params[0].tmpref.size = strlen(password);
	op.params[1].tmpref.buffer = recovery_key;
	op.params[1].tmpref.size = RECOVERY_KEY_LEN;
	op.params[2].tmpref.buffer = archive_name; // dummy value
	op.params[2].tmpref.size = strlen(archive_name); // +1 for null terminator

	// call the TA function
	res = TEEC_InvokeCommand(&tee_ctx->sess, TA_PASSWORD_MANAGER_CMD_CREATE_ARCHIVE, &op, &err_origin);
	
	if (res != TEEC_SUCCESS)
		// errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
		// 	res, err_origin);
		goto emergency_exit;
	
	// print the recovery key as hex with each 4 bytes separated by "-"
	printf("Save the following recovery key to a safe place!\nRecovery key: ");
	for (int i = 0; i < RECOVERY_KEY_LEN; i++)
	{
		printf("%02x", recovery_key[i]);
		if (i % 4 == 3 && i != RECOVERY_KEY_LEN - 1)
			printf("-");
	}

	printf("\n");

	char archive_path[256];
	sprintf(archive_path, "%s/%s", app_dir, archive_name);
	FILE *f = fopen(archive_path, "w");
	if (f == NULL)
	{
		printf("Error creating the archive file.\n");
		return 1;
	}
	fclose(f);

	return 0;

emergency_exit:
	printf("An error occured.\nClosing the application for your safety.\n");
	exit(1);
	return 1;
}

int add_entry(int *fd_archive, char *archive_name, char *password, struct tee_ctx *tee_ctx)
{
	struct pwd_entry entry = {0};
	struct archive_entry archive_entry = {0};

	add_entry_ui(&entry);

	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;
	uint8_t ta_buffer[BUFFER_SIZE] = {0};
	uint8_t hash[SHA256_DIGEST_LENGTH] = {0};

	memcpy(ta_buffer, &entry, sizeof(struct pwd_entry));

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT);

	op.params[0].tmpref.buffer = archive_name;
	op.params[0].tmpref.size = strlen(archive_name);
	op.params[1].tmpref.buffer = password;
	op.params[1].tmpref.size = strlen(password);
	op.params[2].tmpref.buffer = &entry;
	op.params[2].tmpref.size = sizeof(entry);
	op.params[3].tmpref.buffer = ta_buffer;
	op.params[3].tmpref.size = BUFFER_SIZE;

	res = TEEC_InvokeCommand(&tee_ctx->sess, TA_PASSWORD_MANAGER_CMD_ADD_ENTRY, &op, &err_origin);

	if (res != TEEC_SUCCESS) {
		// errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
		// 	res, err_origin);
		goto emergency_exit;
	}

	simple_hash((uint8_t *) entry.site_name, strlen(entry.site_name), hash);

	memcpy(archive_entry.hash, hash, SHA256_DIGEST_LENGTH);

	memcpy(archive_entry.encrypted_entry, ta_buffer, op.params[3].tmpref.size);

	write(*fd_archive, &archive_entry, sizeof(archive_entry));


	return 0;
emergency_exit:
	printf("An error occured (wrong password, maybe?).\nClosing the application for your safety.\n");
	exit(1);
	return 1;
}

int get_entry(int *fd_archive, char *archive_name, char *password, struct tee_ctx *tee_ctx)
{
	char site_name[MAX_SITE_NAME_LEN] = {0};
	struct archive_entry entry = {0};
	char encrypted_entry[ENCRYPTED_ENTRY_SIZE] = {0};
	char *encrypted_entry_ptr = NULL;
	size_t decrypted_len = sizeof(struct pwd_entry);
	char decrypted_entry[sizeof(struct pwd_entry)] = {0};
	struct pwd_entry *entry_ptr;
	uint8_t hash[SHA256_DIGEST_LENGTH] = {0};

	// TEE variables
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;

	get_entry_ui(site_name);
	simple_hash((uint8_t *) site_name, strlen(site_name), hash);

    // Iterate through the archive and find the entry based on the hash
    while (read(*fd_archive, &entry, sizeof(entry)) == sizeof(entry)) {
        if (memcmp(entry.hash, hash, SHA256_DIGEST_LENGTH) == 0) {
            printf("Entry found!\n");
            memcpy(encrypted_entry, entry.encrypted_entry, ENCRYPTED_ENTRY_SIZE);
			encrypted_entry_ptr = encrypted_entry;
            break;
        }
    }
	
	if (encrypted_entry_ptr == NULL)
	{
		printf("Entry not found.\n");
		return 1;
	}

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT);

	op.params[0].tmpref.buffer = archive_name;
	op.params[0].tmpref.size = strlen(archive_name);
	op.params[1].tmpref.buffer = password;
	op.params[1].tmpref.size = strlen(password);
	op.params[2].tmpref.buffer = encrypted_entry_ptr;
	op.params[2].tmpref.size = ENCRYPTED_ENTRY_SIZE;
	op.params[3].tmpref.buffer = decrypted_entry;
	op.params[3].tmpref.size = decrypted_len;

	res = TEEC_InvokeCommand(&tee_ctx->sess, TA_PASSWORD_MANAGER_CMD_GET_ENTRY, &op, &err_origin);

	if (res != TEEC_SUCCESS) {
		// errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
		// 	res, err_origin);
		goto emergency_exit;
	}

	entry_ptr = (struct pwd_entry *) decrypted_entry;

	// TODO: replace with copy to clipboard - not possible in our environment

	printf("Site URL: %s\n", entry_ptr->site_url);
	printf("Site Name: %s\n", entry_ptr->site_name);
	printf("Username: %s\n", entry_ptr->username);
	printf("Password: %s\n", entry_ptr->password);

	memset(&decrypted_entry, 0, sizeof(decrypted_entry));


	return 0;
emergency_exit:
	printf("An error occured (wrong password, maybe?).\nClosing the application for your safety.\n");
	exit(1);
	return 1;
}

int delete_entry(int fd_archive, const char *archive_name)
{
    char site_name[MAX_SITE_NAME_LEN] = {0};
    uint8_t hash[SHA256_DIGEST_LENGTH] = {0};
    struct archive_entry entry;
    int entry_pos = 0;
    int found = 0;
    char buffer[ENCRYPTED_ENTRY_SIZE] = {0};
    off_t remove_pos;
    off_t read_pos;
    ssize_t read_bytes;

	printf("WARNING - experimental feature!\n");

    if (delete_entry_ui(site_name) != 0)
    {
        printf("Aborting.\n");
        return 1;
    }

    simple_hash((uint8_t *)site_name, strlen(site_name), hash);

    while (read(fd_archive, &entry, sizeof(entry)) == sizeof(entry)) {
        if (memcmp(entry.hash, hash, SHA256_DIGEST_LENGTH) == 0) {
            found = 1;
            break;
        }
        entry_pos++;
    }

    if (found == 0)
    {
        printf("Entry not found.\n");
        return 1;
    }

    remove_pos = entry_pos * sizeof(entry);
    read_pos = remove_pos + sizeof(entry);

    while ((read_bytes = pread(fd_archive, buffer, sizeof(buffer), read_pos)) > 0) {
        if (pwrite(fd_archive, buffer, read_bytes, remove_pos) == -1) {
            perror("Failed to write");
            return 1;
        }
        remove_pos += read_bytes;
        read_pos += read_bytes;
    }

    if (ftruncate(fd_archive, remove_pos) == -1) {
        perror("Failed to truncate file");
        return 1;
    }

    return 0;
}

int open_archive(struct tee_ctx *tee_ctx)
{
	char archive_name[MAX_ARCHIVE_NAME_LEN] = {0};
	char password[MAX_PWD_LEN] = {0};
	int choice;
	int fd_archive;

	choice = open_archive_choice_ui(archive_name, password);

	// open the archive file
	char archive_path[256];
	sprintf(archive_path, "%s/%s", app_dir, archive_name);
	fd_archive = open(archive_path, O_RDWR | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	if (fd_archive < 0)
	{
		printf("Error opening the archive file. Are you sure the archive exists?\n");
		return 1;
	}

	if (choice == ADD_ENTRY)
	{
		add_entry(&fd_archive, archive_name, password, tee_ctx);
	}
	else if (choice == GET_ENTRY)
	{
		get_entry(&fd_archive, archive_name, password, tee_ctx);
	}
	else if (choice == DELETE_ENTRY)
	{
		delete_entry(fd_archive, archive_name);
	}
	else
	{
		printf("Invalid choice, closing application for your safety.\n");
	}

	close(fd_archive);

	return 0;
}

int delete_archvie(struct tee_ctx *tee_ctx)
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;

	char archive_name[MAX_ARCHIVE_NAME_LEN];
	char password[MAX_PWD_LEN];

	if (delete_archive_ui(archive_name, password) != 0)
	{
		printf("Aborting.\n");
		return 1;
	}

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = archive_name;
	op.params[0].tmpref.size = strlen(archive_name);
	op.params[1].tmpref.buffer = password;
	op.params[1].tmpref.size = strlen(password);

	res = TEEC_InvokeCommand(&tee_ctx->sess, TA_PASSWORD_MANAGER_CMD_DEL_ARCHIVE, &op, &err_origin);

	if (res != TEEC_SUCCESS)
	{
		// errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
		// 	res, err_origin);
		goto emergency_exit;
	}

	char archive_path[256];
	sprintf(archive_path, "%s/%s", app_dir, archive_name);
	if (remove(archive_path) != 0)
	{
		printf("Error deleting the archive file.\n");
		return 1;
	}

	return 0;

emergency_exit:
	printf("An error occured (maybe wrong password?).\nClosing the application for your safety.\n");
	exit(1);
	return 1;
}

int exit_app(void)
{
	printf("Exiting the Password Manager.\n");
	return 0;
}

int main(void)
{
	struct tee_ctx tee_ctx;

	char dir[MAX_PATH] = {0};
	char *home_dir = getenv("HOME");
	if (home_dir == NULL)
	{
		printf("Error getting the home directory.\n");
		return 1;
	}
	sprintf(dir, "%s/%s", home_dir, ".password_manager/");
	app_dir = dir;


	// check if /etc/password_manager exists, create it if not
	struct stat st = {0};
	if (stat(app_dir, &st) == -1)
	{
		mkdir(app_dir, 0755);
	}

	// Create TEE session
	prepare_tee_session(&tee_ctx);


	// Main UI loop
	printf("Welcome to the Password Manager!\n");
	int choice;



	choice = main_choice_ui();
	switch (choice)
	{
		case CREATE_NEW_ARCHIVE:
			create_archive(&tee_ctx);
			break;
		case OPEN_EXISTING_ARCHIVE:
			open_archive(&tee_ctx);
			break;
		case RESTORE_ARCHIVE:
			break;
		case DELETE_ARCHIVE:
			delete_archvie(&tee_ctx);
			break;
		case EXIT:
			break;
		default:
			goto emergency_exit;
		
	}

exit:
	terminate_tee_session(&tee_ctx);

	exit_app();

	return 0;

emergency_exit:
	printf("An error occured.\nClosing the application for your safety.\n");
	return 1;
}
