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



#include <ta_header.h>

int ENC_DEC_OP = TEE_ALG_AES_ECB_NOPAD;

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

// from OP-TEE xtest suite
void add_attr(size_t *attr_count, TEE_Attribute *attrs, uint32_t attr_id,
		    const void *buf, size_t len)
{
	attrs[*attr_count].attributeID = attr_id;
	attrs[*attr_count].content.ref.buffer = (void *)buf;
	attrs[*attr_count].content.ref.length = len;
	(*attr_count)++;
}

static void convert_pwd_uint8_t(char *pwd, uint8_t *pwd_uint8_t, size_t pwd_len)
{
	for (size_t i = 0; i < pwd_len; i++) {
		pwd_uint8_t[i] = (uint8_t) pwd[i];
	}
}

// TODO: add salt/info?
static TEE_Result derive_key(const char *password, size_t password_len, TEE_ObjectHandle *derivedKey)
{
    // if (key_size < AES256_KEY_SIZE) {
    //     return TEE_ERROR_SHORT_BUFFER
    // }

	// convert pwd to key material
	uint8_t pwd_uint8_t[MAX_PWD_LEN];
	convert_pwd_uint8_t((char *) password, pwd_uint8_t, password_len);

	// dummy infoand salt
	uint8_t info[8] = {0};
	uint8_t salt[8] = {0};
	size_t info_len = 8;
	size_t salt_len = 8;

	size_t param_count = 0;
	TEE_Attribute params[4] = { };

	// handles
	TEE_OperationHandle operation = TEE_HANDLE_NULL;
	TEE_ObjectHandle baseKey = TEE_HANDLE_NULL;

	uint32_t algorithm = TEE_ALG_HKDF_SHA256_DERIVE_KEY;
	uint32_t maxKeySize = 2048;  // This is in bits for AES-256
	TEE_Result res = TEE_AllocateOperation(&operation, algorithm, TEE_MODE_DERIVE, maxKeySize);
	if (res != TEE_SUCCESS) {
		IMSG("TEE_AllocateOperation failed");
		goto err;
	}

	res = TEE_AllocateTransientObject(TEE_TYPE_HKDF_IKM, 8 * password_len, &baseKey);  // key size is in bits
	if (res != TEE_SUCCESS) {
		IMSG("TEE_AllocateTransientObject failed");
		goto err;
	}

	add_attr(&param_count, params, TEE_ATTR_HKDF_IKM, pwd_uint8_t, password_len);

	res = TEE_PopulateTransientObject(baseKey, params, param_count);
	if (res != TEE_SUCCESS) {
		IMSG("TEE_PopulateTransientObject failed");
		goto err;
	}

	res = TEE_SetOperationKey(operation, baseKey);
	if (res != TEE_SUCCESS) {
		IMSG("TEE_SetOperationKey failed");
		goto err;
	}

	// free baseKey
	TEE_FreeTransientObject(baseKey);


	res = TEE_AllocateTransientObject(TEE_TYPE_GENERIC_SECRET, AES256_KEY_SIZE * 8, derivedKey);
	if (res != TEE_SUCCESS) {
		IMSG("TEE_AllocateTransientObject failed");
		goto err;
	}

	param_count = 0;

	add_attr(&param_count, params, TEE_ATTR_HKDF_SALT, salt, salt_len);
	add_attr(&param_count, params, TEE_ATTR_HKDF_INFO, info, info_len);

	params[param_count].attributeID = TEE_ATTR_HKDF_OKM_LENGTH;
	params[param_count].content.value.a = AES256_KEY_SIZE;
	params[param_count].content.value.b = 0;
	param_count++;
	
	TEE_DeriveKey(operation, params, param_count, *derivedKey);

    return TEE_SUCCESS;

err:
	TEE_FreeOperation(operation);
	TEE_FreeTransientObject(baseKey);
	return res;
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
	size_t obtain_key_size = AES256_KEY_SIZE;
	uint8_t key_material_1[AES256_KEY_SIZE], key_material_2[AES256_KEY_SIZE];

	// tee objects to free
	TEE_ObjectHandle derived_key_1 = TEE_HANDLE_NULL;
	TEE_ObjectHandle derived_key_2 = TEE_HANDLE_NULL;
	TEE_ObjectHandle derived_key_1_aes = TEE_HANDLE_NULL;
	TEE_ObjectHandle derived_key_2_aes = TEE_HANDLE_NULL;
	TEE_OperationHandle enc_op_2 = TEE_HANDLE_NULL;
	TEE_OperationHandle enc_op_1 = TEE_HANDLE_NULL;

	TEE_Attribute attr_1;
	TEE_Attribute attr_2;

	// prepare buffers for encrypted master key
	size_t enc_master_key_size = AES256_KEY_SIZE;
	uint8_t enc_master_key_1[AES256_KEY_SIZE];
	uint8_t enc_master_key_2[AES256_KEY_SIZE];

	// for persistant saving
	char archive_name[MAX_ARCHIVE_NAME_LEN] = {0};
	char enc_master_key_1_name[MAX_ARCHIVE_NAME_LEN + 2] = {0};
	char enc_master_key_2_name[MAX_ARCHIVE_NAME_LEN + 2] = {0};
	size_t enc_master_key_name_len = params[2].memref.size + 2;
	TEE_ObjectHandle persistent_obj_1 = TEE_HANDLE_NULL; // need freeing?
	TEE_ObjectHandle persistent_obj_2 = TEE_HANDLE_NULL; // need freeing?


	// copy password, archive name from input buffer
	TEE_MemMove(password, params[0].memref.buffer, params[0].memref.size);
	TEE_MemMove(archive_name, params[2].memref.buffer, params[2].memref.size);

	// prepare key archive names (archive_name + "_1" and archive_name + "_2")
	TEE_MemMove(enc_master_key_1_name, archive_name, params[2].memref.size);
	TEE_MemMove(enc_master_key_2_name, archive_name, params[2].memref.size);
	TEE_MemMove(enc_master_key_1_name + params[2].memref.size, "_1", 2);
	TEE_MemMove(enc_master_key_2_name + params[2].memref.size, "_2", 2);

	// generate random recovery key and master key
	TEE_GenerateRandom(recovery_key, RECOVERY_KEY_LEN);
	TEE_GenerateRandom(master_key, AES256_KEY_SIZE);

	// derive keys from password and recovery key
	if((res = derive_key((char *) password, MAX_PWD_LEN, &derived_key_1)) != TEE_SUCCESS)
		goto cleanup;
	if((res = derive_key((char *) recovery_key, RECOVERY_KEY_LEN, &derived_key_2)) != TEE_SUCCESS)
		goto cleanup;

	// get key material from derived keys
	res = TEE_GetObjectBufferAttribute(derived_key_1, TEE_ATTR_SECRET_VALUE, key_material_1, &obtain_key_size);
	if (res != TEE_SUCCESS)
		goto cleanup;
	
	res = TEE_GetObjectBufferAttribute(derived_key_2, TEE_ATTR_SECRET_VALUE, key_material_2, &obtain_key_size);
	if (res != TEE_SUCCESS)
		goto cleanup;

	// create TEE_TYPE_AES objects
	res = TEE_AllocateTransientObject(TEE_TYPE_AES, AES256_KEY_SIZE * 8, &derived_key_1_aes);
	if (res != TEE_SUCCESS)
		goto cleanup;

	res = TEE_AllocateTransientObject(TEE_TYPE_AES, AES256_KEY_SIZE * 8, &derived_key_2_aes);
	if (res != TEE_SUCCESS)
		goto cleanup;

	TEE_InitRefAttribute(&attr_1, TEE_ATTR_SECRET_VALUE, key_material_1, AES256_KEY_SIZE);
	res = TEE_PopulateTransientObject(derived_key_1_aes, &attr_1, 1);
	if (res != TEE_SUCCESS)
		goto cleanup;

	TEE_InitRefAttribute(&attr_2, TEE_ATTR_SECRET_VALUE, key_material_2, AES256_KEY_SIZE);
	res = TEE_PopulateTransientObject(derived_key_2_aes, &attr_2, 1);
	if (res != TEE_SUCCESS)
		goto cleanup;

	// encrypt the master key with the derived keys

	// change op later from ECB!!!
	res = TEE_AllocateOperation(&enc_op_1, ENC_DEC_OP, TEE_MODE_ENCRYPT, AES256_KEY_SIZE * 8);
	if (res != TEE_SUCCESS)
		goto cleanup;

	res = TEE_SetOperationKey(enc_op_1, derived_key_1_aes);
	if (res != TEE_SUCCESS)
		goto cleanup;

	TEE_CipherInit(enc_op_1, NULL, 0);
	TEE_CipherDoFinal(enc_op_1, master_key, AES256_KEY_SIZE, enc_master_key_1, &enc_master_key_size);

	// change op later from ECB!!!
	res = TEE_AllocateOperation(&enc_op_2, ENC_DEC_OP, TEE_MODE_ENCRYPT, AES256_KEY_SIZE * 8);
	if (res != TEE_SUCCESS)
		goto cleanup;

	res = TEE_SetOperationKey(enc_op_2, derived_key_2_aes);
	if (res != TEE_SUCCESS)
		goto cleanup;

	TEE_CipherInit(enc_op_2, NULL, 0);
	TEE_CipherDoFinal(enc_op_2, master_key, AES256_KEY_SIZE, enc_master_key_2, &enc_master_key_size);

	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, enc_master_key_1_name, enc_master_key_name_len,
									 TEE_DATA_FLAG_ACCESS_WRITE, TEE_HANDLE_NULL, NULL, 0, &persistent_obj_1);

	if (res != TEE_SUCCESS)
		goto cleanup;

	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, enc_master_key_2_name, enc_master_key_name_len,
									 TEE_DATA_FLAG_ACCESS_WRITE, TEE_HANDLE_NULL, NULL, 0, &persistent_obj_2);

	if (res != TEE_SUCCESS)
		goto cleanup;

	res = TEE_WriteObjectData(persistent_obj_1, enc_master_key_1, AES256_KEY_SIZE);
	if (res != TEE_SUCCESS)
		goto cleanup;
	
	res = TEE_WriteObjectData(persistent_obj_2, enc_master_key_2, AES256_KEY_SIZE);
	if (res != TEE_SUCCESS)
		goto cleanup;

	
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

	
	// copy recovery key to output buffer
	TEE_MemMove(params[1].memref.buffer, recovery_key, RECOVERY_KEY_LEN);


	res = TEE_SUCCESS;

cleanup:
	TEE_FreeTransientObject(derived_key_1);
	TEE_FreeTransientObject(derived_key_2);
	TEE_FreeTransientObject(derived_key_1_aes);
	TEE_FreeTransientObject(derived_key_2_aes);
	TEE_FreeOperation(enc_op_1);
	TEE_FreeOperation(enc_op_2);
	return res;
}

/*
 * Sinnce each entry is encrypted with a unique key, we can just 
 * delete the entry from the archive. This can be done in the host
 * application.
 */
TEE_Result delete_entry(uint32_t param_types,
	TEE_Param params[4])
{
	// implemented in host application
	return TEE_SUCCESS;
}

TEE_Result get_master_key(char *file_name, size_t file_name_len, char *password, size_t password_len, TEE_ObjectHandle *master_key)
{
	// TODO: clean this up, add freeing	

	// TEE variables (to free?)
	TEE_ObjectHandle persistent_obj = TEE_HANDLE_NULL; // to load the encrypted master key
	TEE_ObjectHandle derived_key = TEE_HANDLE_NULL; // key derived from password
	TEE_ObjectHandle derived_key_aes = TEE_HANDLE_NULL; // aes object for derived key
	TEE_Attribute attr;
	TEE_OperationHandle dec_op = TEE_HANDLE_NULL; // master key decrypting op
	TEE_Attribute master_key_attr;	

	TEE_Result res;
	
	uint8_t master_key_material[AES256_KEY_SIZE];
	uint8_t enc_master_key[AES256_KEY_SIZE];
	size_t read_size = AES256_KEY_SIZE;
	uint8_t key_material[AES256_KEY_SIZE];
	size_t key_material_size = AES256_KEY_SIZE;

	// open persistent object
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, file_name, file_name_len,
								   TEE_DATA_FLAG_ACCESS_READ, &persistent_obj);
	if (res != TEE_SUCCESS)
		goto cleanup;
	
	// read the encrypted key from the persistent object
	res = TEE_ReadObjectData(persistent_obj, enc_master_key, AES256_KEY_SIZE, &read_size);
	if (res != TEE_SUCCESS)
		goto cleanup;

	// derive key from password
	res = derive_key(password, password_len, &derived_key);
	if (res != TEE_SUCCESS)
		goto cleanup;

	// get key material from derived key
	res = TEE_GetObjectBufferAttribute(derived_key, TEE_ATTR_SECRET_VALUE, key_material, &key_material_size);
	if (res != TEE_SUCCESS)
		goto cleanup;

	// create TEE_TYPE_AES object for the derived key
	res = TEE_AllocateTransientObject(TEE_TYPE_AES, AES256_KEY_SIZE * 8, &derived_key_aes);
	if (res != TEE_SUCCESS)
		goto cleanup;

	// populate the derived key object
	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key_material, AES256_KEY_SIZE);
	res = TEE_PopulateTransientObject(derived_key_aes, &attr, 1);
	if (res != TEE_SUCCESS)
		goto cleanup;

	// decrypt the master key
	res = TEE_AllocateOperation(&dec_op, ENC_DEC_OP, TEE_MODE_DECRYPT, AES256_KEY_SIZE * 8);
	if (res != TEE_SUCCESS)
		goto cleanup;

	// set the derived key aes as the key for the decryption operation
	res = TEE_SetOperationKey(dec_op, derived_key_aes);
	if (res != TEE_SUCCESS)
		goto cleanup;

	// decrypt the master key
	TEE_CipherInit(dec_op, NULL, 0);
	TEE_CipherDoFinal(dec_op, enc_master_key, AES256_KEY_SIZE, master_key_material, &read_size);

	// populate the master key object
	TEE_InitRefAttribute(&master_key_attr, TEE_ATTR_SECRET_VALUE, master_key_material, AES256_KEY_SIZE);
	res = TEE_PopulateTransientObject(*master_key, &master_key_attr, 1);

cleanup:
	TEE_FreeTransientObject(derived_key);
	TEE_FreeTransientObject(derived_key_aes);
	TEE_FreeOperation(dec_op);

	return res;
}

TEE_Result add_entry(uint32_t param_types,
	TEE_Param params[4])
{
	// check param types
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	// TEE variables
	TEE_Result res;

	// function input/output
	char archive_name[MAX_ARCHIVE_NAME_LEN] = {0};
	char password[MAX_PWD_LEN] = {0};
	struct pwd_entry entry = {0};
	size_t entry_size = sizeof(struct pwd_entry);
	char enc_master_key_1_name[MAX_ARCHIVE_NAME_LEN + 2] = {0};
	uint8_t enc_entry[BUFFER_SIZE] = {0};
	size_t enc_entry_len = BUFFER_SIZE;

	// TEE objects
	TEE_ObjectHandle aes_key = TEE_HANDLE_NULL;
	TEE_OperationHandle enc_op = TEE_HANDLE_NULL;

	// copy archive name, password, pwd_entry from input buffer
	TEE_MemMove(archive_name, params[0].memref.buffer, params[0].memref.size);
	TEE_MemMove(password, params[1].memref.buffer, params[1].memref.size);
	TEE_MemMove(&entry, params[2].memref.buffer, entry_size);

	// prepare key archive names (archive_name + "_1")
	TEE_MemMove(enc_master_key_1_name, archive_name, params[0].memref.size);
	TEE_MemMove(enc_master_key_1_name + params[0].memref.size, "_1", 2);

	// allocate the master key object (as AES)
	res = TEE_AllocateTransientObject(TEE_TYPE_AES, AES256_KEY_SIZE * 8, &aes_key);
	if (res != TEE_SUCCESS)
		goto cleanup;

	// get the aes key
	res = get_master_key(enc_master_key_1_name, params[0].memref.size + 2, password, params[1].memref.size, &aes_key);
	if (res != TEE_SUCCESS)
		goto cleanup;
	
	// prepare the encryption operation
	res = TEE_AllocateOperation(&enc_op, ENC_DEC_OP, TEE_MODE_ENCRYPT, AES256_KEY_SIZE * 8);
	if (res != TEE_SUCCESS)
		goto cleanup;

	// set the key for the encryption operation
	res = TEE_SetOperationKey(enc_op, aes_key);
	if (res != TEE_SUCCESS)
		goto cleanup;

	// encrypt the pwd_entry
	TEE_CipherInit(enc_op, NULL, 0);
	TEE_CipherDoFinal(enc_op, (uint8_t *) &entry, sizeof(struct pwd_entry), enc_entry, &enc_entry_len);

	// copy the encrypted pwd_entry to the output buffer
	TEE_MemMove(params[3].memref.buffer, enc_entry, enc_entry_len);
	params[3].memref.size = enc_entry_len;
	
cleanup:
	TEE_FreeTransientObject(aes_key);
	TEE_FreeOperation(enc_op);

	return TEE_SUCCESS;

}

TEE_Result get_entry(uint32_t param_types,
	TEE_Param params[4])
{
	// check param types
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	// TEE variables
	TEE_Result res;

	// function input/output
	char archive_name[MAX_ARCHIVE_NAME_LEN] = {0};
	char password[MAX_PWD_LEN] = {0};
	char enc_master_key_1_name[MAX_ARCHIVE_NAME_LEN + 2] = {0};
	uint8_t enc_entry[ENCRYPTED_ENTRY_SIZE] = {0};
	size_t enc_entry_len = ENCRYPTED_ENTRY_SIZE;
	uint8_t dec_entry[BUFFER_SIZE] = {0};
	size_t dec_entry_len = BUFFER_SIZE;

	// TEE objects
	TEE_ObjectHandle aes_key = TEE_HANDLE_NULL;
	TEE_OperationHandle dec_op = TEE_HANDLE_NULL;

	// copy archive name, password, pwd_entry from input buffer
	TEE_MemMove(archive_name, params[0].memref.buffer, params[0].memref.size);
	TEE_MemMove(password, params[1].memref.buffer, params[1].memref.size);
	TEE_MemMove(enc_entry, params[2].memref.buffer, params[2].memref.size);

	// prepare key archive names (archive_name + "_1")
	TEE_MemMove(enc_master_key_1_name, archive_name, params[0].memref.size);
	TEE_MemMove(enc_master_key_1_name + params[0].memref.size, "_1", 2);

	// allocate the master key object (as AES)
	res = TEE_AllocateTransientObject(TEE_TYPE_AES, AES256_KEY_SIZE * 8, &aes_key);
	if (res != TEE_SUCCESS)
		goto cleanup;

	// get the aes key
	res = get_master_key(enc_master_key_1_name, params[0].memref.size + 2, password, params[1].memref.size, &aes_key);
	if (res != TEE_SUCCESS)
		goto cleanup;

	// prepare the decryption operation
	res = TEE_AllocateOperation(&dec_op, ENC_DEC_OP, TEE_MODE_DECRYPT, AES256_KEY_SIZE * 8);
	if (res != TEE_SUCCESS)
		goto cleanup;

	// set the key for the decryption operation
	res = TEE_SetOperationKey(dec_op, aes_key);
	if (res != TEE_SUCCESS)
		goto cleanup;

	// decrypt the pwd_entry
	TEE_CipherInit(dec_op, NULL, 0);
	TEE_CipherDoFinal(dec_op, enc_entry, ENCRYPTED_ENTRY_SIZE, dec_entry, &dec_entry_len);

	// copy the decrypted pwd_entry to the output buffer
	TEE_MemMove(params[3].memref.buffer, dec_entry, dec_entry_len);
	params[3].memref.size = dec_entry_len;

cleanup:
	TEE_FreeTransientObject(aes_key);
	TEE_FreeOperation(dec_op);

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
		return add_entry(param_types, params);
	case TA_PASSWORD_MANAGER_CMD_GET_ENTRY:
		return get_entry(param_types, params);
	case TA_PASSWORD_MANAGER_CMD_DEL_ENTRY:
		return delete_entry(param_types, params);
	case TA_PASSWORD_MANAGER_CMD_UPDATE_ENTRY:
		return TEE_ERROR_NOT_IMPLEMENTED;
	case TA_PASSWORD_MANAGER_CMD_DEL_ARCHIVE:
		return TEE_ERROR_NOT_IMPLEMENTED;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
