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

// Custom header file
#include "password_manager.h"

// function declarations from tee.c
void prepare_tee_session(struct tee_ctx *ctx);
void terminate_tee_session(struct tee_ctx *ctx);

// function declarations from ui.c
int main_choice_ui();

int get_entry(struct tee_ctx *tee_ctx)
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;

	// actual pwd managger calls
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_MEMREF_TEMP_INPUT, TEEC_NONE);

	// prepare buffers for password and for recovery key

	char password[MAX_PWD_LEN];
	char recovery_key[RECOVERY_KEY_LEN];

	memset(password, 0, sizeof(password));
	memset(recovery_key, 0, sizeof(recovery_key));

	// set password to dummy value
	strcpy(password, "password");
	// set archive name to dummy value
	char archive_name[] = "archive_name";

	op.params[0].tmpref.buffer = password;
	op.params[0].tmpref.size = MAX_PWD_LEN;
	op.params[1].tmpref.buffer = recovery_key;
	op.params[1].tmpref.size = RECOVERY_KEY_LEN;
	op.params[2].tmpref.buffer = archive_name; // dummy value
	op.params[2].tmpref.size = strlen(archive_name) + 1; // +1 for null terminator

	// call the TA function
	res = TEEC_InvokeCommand(&tee_ctx->sess, TA_PASSWORD_MANAGER_CMD_GET_ENTRY, &op, &err_origin);
	
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
	
	return 0;
}

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

	char password[MAX_PWD_LEN];
	char recovery_key[RECOVERY_KEY_LEN];

	memset(password, 0, sizeof(password));
	memset(recovery_key, 0, sizeof(recovery_key));

	// set password to dummy value
	strcpy(password, "password");
	// set archive name to dummy value
	char archive_name[] = "archive_name";

	op.params[0].tmpref.buffer = password;
	op.params[0].tmpref.size = MAX_PWD_LEN;
	op.params[1].tmpref.buffer = recovery_key;
	op.params[1].tmpref.size = RECOVERY_KEY_LEN;
	op.params[2].tmpref.buffer = archive_name; // dummy value
	op.params[2].tmpref.size = strlen(archive_name) + 1; // +1 for null terminator

	// call the TA function
	res = TEEC_InvokeCommand(&tee_ctx->sess, TA_PASSWORD_MANAGER_CMD_CREATE_ARCHIVE, &op, &err_origin);
	
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
	
	// print the recovery key as hex with each 4 bytes separated by "-"
	printf("Recovery key: ");
	for (int i = 0; i < RECOVERY_KEY_LEN; i++)
	{
		printf("%02x", recovery_key[i]);
		if (i % 4 == 3 && i != RECOVERY_KEY_LEN - 1)
			printf("-");
	}

	printf("\n");
	return 0;
}


int main(void)
{
	// LATER MOVE THIS OUT OF MAIN

	struct tee_ctx tee_ctx;

	// Create TEE session
	prepare_tee_session(&tee_ctx);


	// Main UI loop
	printf("Welcome to the Password Manager!\n");
	int choice;
	choice = main_choice_ui();
	printf("Choice: %d\n", choice);

	switch (choice)
	{
		case CREATE_NEW_ARCHIVE:
			create_archive(&tee_ctx);
			break;
		case OPEN_EXISTING_ARCHIVE:
			get_entry(&tee_ctx);
			break;
		default:
			goto emergency_exit;
	}

	terminate_tee_session(&tee_ctx);


	return 0;

emergency_exit:
	printf("An error occured.\nClosing the application for your safety.\n");
	return 1;
}
