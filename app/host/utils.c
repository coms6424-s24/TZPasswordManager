#include "password_manager.h"


// Adapted from OP-TEE examples (Secure Storage)
void prepare_tee_session(struct tee_ctx *ctx)
{
	TEEC_UUID uuid = TA_PASSWORD_MANAGER_UUID;
	uint32_t origin;
	TEEC_Result res;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx->ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	/* Open a session with the TA */
	res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, origin);
}

// Adapted from OP-TEE examples (Secure Storage)
void terminate_tee_session(struct tee_ctx *ctx)
{
	TEEC_CloseSession(&ctx->sess);
	TEEC_FinalizeContext(&ctx->ctx);
}

// inspired by http://www.cse.yorku.ca/~oz/hash.html and extended to 32 bytes by ChatGPT
void simple_hash(const uint8_t *data, size_t data_len, uint8_t *out_hash) {
    uint32_t hash[8] = {0};  
    uint32_t temp;
    size_t i;

    for (i = 0; i < data_len; i++) {
        temp = data[i];
        hash[i % 8] = (hash[i % 8] + (temp << (i % 24))) ^ (temp >> (i % 8));
    }

    for (i = 0; i < 8; i++) {
        hash[i] ^= hash[(i + 3) % 8] << 5;
        hash[i] ^= hash[(i + 5) % 8] >> 3;
    }

    memcpy(out_hash, hash, SHA256_DIGEST_LENGTH);
}