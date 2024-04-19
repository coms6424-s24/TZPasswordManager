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

static TEE_Result derive_key(const char *password, size_t password_len, TEE_ObjectHandle *derivedKey)
{
//     if (key_size < AES256_KEY_SIZE) {
//         return TEE_ERROR_SHORT_BUFFER;
//     }
	IMSG("derive_key called");
	TEE_OperationHandle operation;
	uint32_t algorithm = TEE_ALG_HKDF_SHA512_DERIVE_KEY;
	uint32_t maxKeySize = 256;  // This is in bits for AES-256
	TEE_Result res = TEE_AllocateOperation(&operation, algorithm, TEE_MODE_DERIVE, maxKeySize);
	if (res != TEE_SUCCESS) {
		IMSG("TEE_AllocateOperation failed");
		// print res to see what the error is
		IMSG("res: %d", res);
		// Handle error
		return res;
	}
	IMSG("TEE_AllocateOperation success");

	TEE_ObjectHandle baseKey;
	res = TEE_AllocateTransientObject(TEE_TYPE_GENERIC_SECRET, 8 * password_len, &baseKey);  // key size is in bits
	if (res != TEE_SUCCESS) {
		// Handle error
		IMSG("TEE_AllocateTransientObject failed");
	}

	TEE_Attribute attr;
	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, password, password_len);
	res = TEE_PopulateTransientObject(baseKey, &attr, 1);
	if (res != TEE_SUCCESS) {
		TEE_FreeTransientObject(baseKey);
		// Handle error
		IMSG("TEE_PopulateTransientObject failed");
	}

	res = TEE_SetOperationKey(operation, baseKey);
	if (res != TEE_SUCCESS) {
		TEE_FreeTransientObject(baseKey);
		// Handle error
		IMSG("TEE_SetOperationKey failed");
	}

	res = TEE_AllocateTransientObject(TEE_TYPE_AES, maxKeySize, derivedKey);
	if (res != TEE_SUCCESS) {
		// Handle error
		IMSG("TEE_AllocateTransientObject failed");
	}

	TEE_DeriveKey(operation, NULL, 0, *derivedKey);



    // TEE_Result res;
    // TEE_OperationHandle digest_op = TEE_HANDLE_NULL;

    // // Initialize a context for SHA-256
    // res = TEE_AllocateOperation(&digest_op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    // if (res != TEE_SUCCESS) {
    //     return res;
    // }

    // // Reset the operation
    // TEE_DigestUpdate(digest_op, (const uint8_t *)password, password_size);

    // // Produce the hash (key)
    // size_t hash_size = AES256_KEY_SIZE;
    // res = TEE_DigestDoFinal(digest_op, NULL, 0, key, &hash_size);

    // // Clean up
    // TEE_FreeOperation(digest_op);

    // // Ensure the key size is correct
    // if (res == TEE_SUCCESS && hash_size != AES256_KEY_SIZE) {
    //     res = TEE_ERROR_GENERIC;
    // }

    return TEE_SUCCESS;
}

// static TEE_Result create_key_object(TEE_ObjectHandle *obj_handle, uint8_t *key, size_t keysize_bytes)
// {
// 	TEE_Result res;

// 	res = TEE_AllocateTransientObject(TEE_TYPE_AES, keysize_bytes * 8, obj_handle);
// 	if (res != TEE_SUCCESS)
// 		return res;

// 	TEE_Attribute attr;
// 	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, keysize_bytes);
// 	res = TEE_PopulateTransientObject(*obj_handle, &attr, 1);
// 	if (res != TEE_SUCCESS)
// 		return res;
	
// 	return TEE_SUCCESS;
// }

static TEE_Result create_archive(uint32_t param_types,
	TEE_Param params[4])
{
	// check param types
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	// init stack/heap variables
	TEE_Result res;
	uint8_t recovery_key[RECOVERY_KEY_LEN] = {0};
	uint8_t password[MAX_PWD_LEN] = {0};
	uint8_t master_key[AES256_KEY_SIZE] = {0};
	size_t  master_key_size = AES256_KEY_SIZE;

	// copy password from input buffer
	TEE_MemMove(password, params[0].memref.buffer, params[0].memref.size);

	// generate random recovery key and master key
	TEE_GenerateRandom(recovery_key, RECOVERY_KEY_LEN);
	TEE_GenerateRandom(master_key, AES256_KEY_SIZE);

	// prepare the derived keys
	// uint8_t derived_key_1[AES256_KEY_SIZE];
	// uint8_t derived_key_2[AES256_KEY_SIZE];

	TEE_ObjectHandle derived_key_1 = TEE_HANDLE_NULL;
	TEE_ObjectHandle derived_key_2 = TEE_HANDLE_NULL;

	res = derive_key((char *) password, MAX_PWD_LEN, &derived_key_1);

	return TEE_SUCCESS;

	TEE_ObjectInfo key_info;
	uint8_t *key_buffer;
	uint32_t read_bytes;

	// Retrieve information about the key object
	res = TEE_GetObjectInfo1(derived_key_1, &key_info);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to get key info: 0x%x", res);
	} else {
		// Allocate memory for the key buffer
		key_buffer = TEE_Malloc(key_info.keySize / 8, TEE_MALLOC_FILL_ZERO);
		if (!key_buffer) {
			EMSG("Failed to allocate memory for key buffer");
		} else {
			// Read the key data
			res = TEE_GetObjectBufferAttribute(derived_key_1, TEE_ATTR_SECRET_VALUE, key_buffer, &read_bytes);
			if (res != TEE_SUCCESS) {
				EMSG("Failed to read key buffer: 0x%x", res);
			} else {
				// Print the key in hexadecimal format
				for (uint32_t i = 0; i < read_bytes; i++) {
					DMSG("%02x", key_buffer[i]);
				}
				DMSG("\n");  // New line after printing the key
			}
			TEE_Free(key_buffer); // Free the allocated buffer
		}
	}


	// res = derive_key(recovery_key, RECOVERY_KEY_LEN, derived_key_1, AES256_KEY_SIZE);
	// if (res != TEE_SUCCESS)
	// 	goto cleanup;

	// res = derive_key((char *) password, MAX_PWD_LEN, derived_key_2, AES256_KEY_SIZE);
	// if (res != TEE_SUCCESS)
	// 	goto cleanup;

	// TEE_ObjectHandle transient_key_1 = TEE_HANDLE_NULL;
	// TEE_ObjectHandle tranisent_key_2 = TEE_HANDLE_NULL;

	// res = create_key_object(&transient_key_1, derived_key_1, AES256_KEY_SIZE);
	// if (res != TEE_SUCCESS)
	// 	goto cleanup;

	// res = create_key_object(&tranisent_key_2, derived_key_2, AES256_KEY_SIZE);
	// if (res != TEE_SUCCESS)
	// 	goto cleanup;
	
	// // encrypt the master key with the derived keys
	// // TODO

	// // get hash of the master key - doesn't work?
	// uint8_t master_key_hash[AES256_KEY_SIZE];
	// TEE_OperationHandle hash_op = TEE_HANDLE_NULL;
	// res = TEE_AllocateOperation(&hash_op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
	// if (res != TEE_SUCCESS)
	// 	goto cleanup;

	// res = TEE_DigestDoFinal(hash_op, master_key, AES256_KEY_SIZE, master_key_hash, &master_key_size);
	// if (res != TEE_SUCCESS)
	// 	goto cleanup;

	
	// // copy recovery key to output buffer
	// TEE_MemMove(params[1].memref.buffer, recovery_key, RECOVERY_KEY_LEN);


	return TEE_SUCCESS;

}

/*
 * Sinnce each entry is encrypted with a unique key, we can just 
 * delete the entry from the archive. This can be done in the host
 * application.
 */
TEE_Result delete_entry(param_types, params)
{
	// implemented in host application
	return TEE_SUCCESS;
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
	case TA_PASSWORD_MANAGER_CMD_CREATE_ARCHIVE:
		return create_archive(param_types, params);
	case TA_PASSWORD_MANAGER_CMD_RESTORE_ARCHIVE:
		return TEE_ERROR_NOT_IMPLEMENTED;
	case TA_PASSWORD_MANAGER_CMD_ADD_ENTRY:
		return TEE_ERROR_NOT_IMPLEMENTED;
	case TA_PASSWORD_MANAGER_CMD_GET_ENTRY:
		return TEE_ERROR_NOT_IMPLEMENTED;
	case TA_PASSWORD_MANAGER_CMD_DEL_ENTRY:
		return delete_entry(param_types, params);
	case TA_PASSWORD_MANAGER_CMD_UPDATE_ENTRY:
		return TEE_ERROR_NOT_IMPLEMENTED;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
