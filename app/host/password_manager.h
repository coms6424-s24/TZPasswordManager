#ifndef PASSWORD_MANAGER_H
#define PASSWORD_MANAGER_H

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include <password_manager_ta.h>

#include <err.h>

#define INVALID_CHOICE -1
#define CREATE_NEW_ARCHIVE 0
#define OPEN_EXISTING_ARCHIVE 1
#define RESTORE_ARCHIVE 2
#define EXIT 3

// Adapted from OP-TEE examples (Secure Storage)
/* TEE resources */
struct tee_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

// tee.c
void prepare_tee_session(struct tee_ctx *ctx);
void terminate_tee_session(struct tee_ctx *ctx);

// ui.c
int main_choice_ui();

#endif /* PASSWORD_MANAGER_H */