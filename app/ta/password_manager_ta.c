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

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <password_manager_ta.h>

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	/*
	 * The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */
	IMSG("Hello World!\n");

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
	IMSG("Goodbye!\n");
}

static TEE_Result inc_value(uint32_t param_types,
	TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	IMSG("Got value: %u from NW", params[0].value.a);

	// gen test
	char *buf = NULL;
	buf = TEE_Malloc(16, 0);
	if (!buf)
		return TEE_ERROR_OUT_OF_MEMORY;
	TEE_GenerateRandom(buf, 16);
	IMSG("Generated random data:");
	// convert to hex representation and print
	for (int i = 0; i < 16; i++)
		IMSG("%02hhx", buf[i]);

	params[0].value.a++;
	IMSG("Increase value to: %u", params[0].value.a);

	return TEE_SUCCESS;
}

static TEE_Result dec_value(uint32_t param_types,
	TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	IMSG("Got value: %u from NW", params[0].value.a);
	params[0].value.a--;
	IMSG("Decrease value to: %u", params[0].value.a);

	return TEE_SUCCESS;
}

TEE_Result derive_key(const char *password, size_t password_size, uint8_t *key, size_t key_size) {
    if (key_size < AES256_KEY_SIZE) {
        return TEE_ERROR_SHORT_BUFFER;
    }

    TEE_Result res;
    TEE_OperationHandle digest_op = TEE_HANDLE_NULL;

    // Initialize a context for SHA-256
    res = TEE_AllocateOperation(&digest_op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    if (res != TEE_SUCCESS) {
        return res;
    }

    // Reset the operation
    TEE_DigestUpdate(digest_op, (const uint8_t *)password, password_size);

    // Produce the hash (key)
    size_t hash_size = AES256_KEY_SIZE;
    res = TEE_DigestDoFinal(digest_op, NULL, 0, key, &hash_size);

    // Clean up
    TEE_FreeOperation(digest_op);

    // Ensure the key size is correct
    if (res == TEE_SUCCESS && hash_size != AES256_KEY_SIZE) {
        res = TEE_ERROR_GENERIC;
    }

    return res;
}

static TEE_Result create_archive(uint32_t param_types,
	TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	TEE_Result res;

	char *recover_key = TEE_Malloc(RECOVERY_KEY_LEN, 0);
	if (!recover_key)
		return TEE_ERROR_OUT_OF_MEMORY;

	char *password = TEE_Malloc(MAX_PWD_LEN, 0);
	if (!password)
	{
		TEE_Free(recover_key);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	// copy password from input buffer
	TEE_MemMove(password, params[0].memref.buffer, params[0].memref.size);

	// generate random recovery key
	TEE_GenerateRandom(recover_key, RECOVERY_KEY_LEN);

	// // prepare derive AES key
	// TEE_ObjectHandle derive_key = TEE_HANDLE_NULL;
	// TEE_OperationHandle derive_op = TEE_HANDLE_NULL;
 
	// res = TEE_AllocateOperation(&derive_op, TEE_ALG_HKDF, TEE_MODE_DERIVE, 0);
	// if (res != TEE_SUCCESS)
	// 	goto cleanup;

	// res = TEE_AllocateTransientObject(TEE_TYPE_AES, 256, &derive_key);
	// if (res != TEE_SUCCESS)
	// 	goto cleanup;

	// res = TEE_PopulateTransientObject(derive_key, (TEE_Attribute *)NULL, 0);
	// if (res != TEE_SUCCESS)
	// 	goto cleanup;

	// TEE_Attribute attrs[1];
	// attrs[0].attributeID = TEE_ATTR_HKDF_SALT;
	// attrs[0].content.ref.buffer = password;

	// TEE_DeriveKey(derive_op, attrs, 1, derive_key);

	// // print the derived key for debugging, in hex
	// IMSG("Derived key: ");
	// for (int i = 0; i < RECOVERY_KEY_LEN; i++)
	// {
	// 	IMSG("%02x", recover_key[i]);
	// 	if (i % 4 == 3)
	// 		IMSG("-");
	// }

	uint8_t master_key[AES256_KEY_SIZE];

	res = derive_key(password, MAX_PWD_LEN, master_key, AES256_KEY_SIZE);
	if (res != TEE_SUCCESS)
	{
		TEE_Free(recover_key);
		TEE_Free(password);
		return res;
	}

	// // print the derived key for debugging, in hex
	// IMSG("Derived key: ");
	// for (int i = 0; i < AES256_KEY_SIZE; i++)
	// {
	// 	IMSG("%02x", master_key[i]);
	// 	if (i % 4 == 3)
	// 		IMSG("-");
	// }




	// copy recovery key to output buffer
	TEE_MemMove(params[1].memref.buffer, recover_key, RECOVERY_KEY_LEN);

	TEE_Free(recover_key);
	return TEE_SUCCESS;

cleanup:
	TEE_Free(recover_key);
	TEE_Free(password);
	return res;

}



/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */

	switch (cmd_id) {
	case TA_PASSWORD_MANAGER_CMD_INC_VALUE:
		return inc_value(param_types, params);
	case TA_PASSWORD_MANAGER_CMD_DEC_VALUE:
		return dec_value(param_types, params);
	case TA_PASSWORD_MANAGER_CMD_CREATE_ARCHIVE:
		return create_archive(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
