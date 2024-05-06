#ifndef PASSWORD_MANAGER_H
#define PASSWORD_MANAGER_H

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include <password_manager_ta.h>

#include <err.h>

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>

#define INVALID_CHOICE -1
#define CREATE_NEW_ARCHIVE 0
#define OPEN_EXISTING_ARCHIVE 1
#define RESTORE_ARCHIVE 2
#define DELETE_ARCHIVE 3
#define EXIT 4

#define ADD_ENTRY 5
#define GET_ENTRY 6

// Adapted from OP-TEE examples (Secure Storage)
/* TEE resources */
struct tee_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

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

#endif /* PASSWORD_MANAGER_H */