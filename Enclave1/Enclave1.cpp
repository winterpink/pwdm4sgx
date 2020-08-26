/*
 * Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


// Enclave1.cpp : Defines the exported functions for the .so application
#include "sgx_eid.h"
#include "Enclave1_t.h"
#include "EnclaveMessageExchange.h"
#include "error_codes.h"
#include "Utility_E1.h"
#include "sgx_dh.h"
#include <map>
#include <binn/binn.h>
#include <scrypt/crypto_scrypt.h>

#define UNUSED(val) (void)(val)

std::map<sgx_enclave_id_t, dh_session_t>g_src_session_info_map;

static uint32_t e1_foo1_wrapper(ms_in_msg_exchange_t *ms, size_t param_lenth, char** resp_buffer, size_t* resp_length);

//Function pointer table containing the list of functions that the enclave exposes
const struct {
    size_t num_funcs;
    const void* table[1];
} func_table = {
    1,
    {
        (const void*)e1_foo1_wrapper,
    }
};

//Makes use of the sample code function to establish a secure channel with the destination enclave (Test Vector)
uint32_t test_create_session(sgx_enclave_id_t src_enclave_id,
                         sgx_enclave_id_t dest_enclave_id)
{
    ATTESTATION_STATUS ke_status = SUCCESS;
    dh_session_t dest_session_info;

    //Core reference code function for creating a session
    ke_status = create_session(src_enclave_id, dest_enclave_id, &dest_session_info);

    //Insert the session information into the map under the corresponding destination enclave id
    if(ke_status == SUCCESS)
    {
        g_src_session_info_map.insert(std::pair<sgx_enclave_id_t, dh_session_t>(dest_enclave_id, dest_session_info));
    }
    memset(&dest_session_info, 0, sizeof(dh_session_t));
    return ke_status;
}

//Makes use of the sample code function to do an enclave to enclave call (Test Vector)
uint32_t test_enclave_to_enclave_call(sgx_enclave_id_t src_enclave_id,
                                          sgx_enclave_id_t dest_enclave_id)
{
    ATTESTATION_STATUS ke_status = SUCCESS;
    uint32_t var1,var2;
    uint32_t target_fn_id, msg_type;
    char* marshalled_inp_buff;
    size_t marshalled_inp_buff_len;
    char* out_buff;
    size_t out_buff_len;
    dh_session_t *dest_session_info;
    size_t max_out_buff_size;
    char* retval;

    var1 = 0x4;
    var2 = 0x5;
    target_fn_id = 0;
    msg_type = ENCLAVE_TO_ENCLAVE_CALL;
    max_out_buff_size = 50;

    //Marshals the input parameters for calling function foo1 in Enclave2 into a input buffer
    ke_status = marshal_input_parameters_e2_foo1(target_fn_id, msg_type, var1, var2, &marshalled_inp_buff, &marshalled_inp_buff_len);
    if(ke_status != SUCCESS)
    {
        return ke_status;
    }

    //Search the map for the session information associated with the destination enclave id of Enclave2 passed in
    std::map<sgx_enclave_id_t, dh_session_t>::iterator it = g_src_session_info_map.find(dest_enclave_id);
    if(it != g_src_session_info_map.end())
    {
          dest_session_info = &it->second;
    }
    else
    {
        SAFE_FREE(marshalled_inp_buff);
        return INVALID_SESSION;
    }

    //Core Reference Code function
    ke_status = send_request_receive_response(src_enclave_id, dest_enclave_id, dest_session_info, marshalled_inp_buff,
                                            marshalled_inp_buff_len, max_out_buff_size, &out_buff, &out_buff_len);


    if(ke_status != SUCCESS)
    {
        SAFE_FREE(marshalled_inp_buff);
        SAFE_FREE(out_buff);
        return ke_status;
    }

    //Un-marshal the return value and output parameters from foo1 of Enclave 2
    ke_status = unmarshal_retval_and_output_parameters_e2_foo1(out_buff, &retval);
    if(ke_status != SUCCESS)
    {
        SAFE_FREE(marshalled_inp_buff);
        SAFE_FREE(out_buff);
        return ke_status;
    }

    SAFE_FREE(marshalled_inp_buff);
    SAFE_FREE(out_buff);
    SAFE_FREE(retval);
    return SUCCESS;
}

//Makes use of the sample code function to do a generic secret message exchange (Test Vector)
uint32_t test_message_exchange(sgx_enclave_id_t src_enclave_id,
                               sgx_enclave_id_t dest_enclave_id, 
                               char* message, int messagelen)
{
    ATTESTATION_STATUS ke_status = SUCCESS;
    uint32_t target_fn_id, msg_type;
    char* marshalled_inp_buff;
    size_t marshalled_inp_buff_len;
    char* out_buff;
    size_t out_buff_len;
    dh_session_t *dest_session_info;
    size_t max_out_buff_size;
    char* secret_response;
    uint32_t secret_data;

    target_fn_id = 0;
    msg_type = MESSAGE_EXCHANGE;
    max_out_buff_size = 50;
    secret_data = 0x12345678; //Secret Data here is shown only for purpose of demonstration.

    //Marshals the secret data into a buffer
    // ke_status = marshal_message_exchange_request(target_fn_id, msg_type, secret_data, &marshalled_inp_buff, &marshalled_inp_buff_len);
    // if(ke_status != SUCCESS)
    // {
    //     return ke_status;
    // }
    char str[messagelen + 1];
    memcpy(str, message, messagelen);
    str[messagelen] = '\0';
    ke_status = marshal_message_exchange_request3(target_fn_id, msg_type, str, &marshalled_inp_buff, &marshalled_inp_buff_len);
    if(ke_status != SUCCESS)
    {
        return ke_status;
    }
   
    //Search the map for the session information associated with the destination enclave id passed in
    std::map<sgx_enclave_id_t, dh_session_t>::iterator it = g_src_session_info_map.find(dest_enclave_id);
    if(it != g_src_session_info_map.end())
    {
         dest_session_info = &it->second;
    }
    else
    {
        SAFE_FREE(marshalled_inp_buff);
        return INVALID_SESSION;
    }

    // char* temp_in_buf = malloc(20);
    // temp_in_buf[0] = 'b';
    // temp_in_buf[1] = 'r';
    // temp_in_buf[2] = 'e';
    // temp_in_buf[3] = '\0';





    //Core Reference Code function
    ke_status = send_request_receive_response(src_enclave_id, dest_enclave_id, dest_session_info, marshalled_inp_buff,
                                                marshalled_inp_buff_len, max_out_buff_size, &out_buff, &out_buff_len);
    if(ke_status != SUCCESS)
    {
        SAFE_FREE(marshalled_inp_buff);
        SAFE_FREE(out_buff);
        return ke_status;
    }

    //Un-marshal the secret response data
    ke_status = umarshal_message_exchange_response(out_buff, &secret_response);
    if(ke_status != SUCCESS)
    {
        SAFE_FREE(marshalled_inp_buff);
        SAFE_FREE(out_buff);
        return ke_status;
    }

    SAFE_FREE(marshalled_inp_buff);
    SAFE_FREE(out_buff);
    SAFE_FREE(secret_response);
    return SUCCESS;
}


//Makes use of the sample code function to close a current session
uint32_t test_close_session(sgx_enclave_id_t src_enclave_id,
                                sgx_enclave_id_t dest_enclave_id)
{
    dh_session_t dest_session_info;
    ATTESTATION_STATUS ke_status = SUCCESS;
    //Search the map for the session information associated with the destination enclave id passed in
    std::map<sgx_enclave_id_t, dh_session_t>::iterator it = g_src_session_info_map.find(dest_enclave_id);
    if(it != g_src_session_info_map.end())
    {
        dest_session_info = it->second;
    }
    else
    {
        return NULL;
    }

    //Core reference code function for closing a session
    ke_status = close_session(src_enclave_id, dest_enclave_id);

    //Erase the session information associated with the destination enclave id
    g_src_session_info_map.erase(dest_enclave_id);
    return ke_status;
}

//Function that is used to verify the trust of the other enclave
//Each enclave can have its own way verifying the peer enclave identity
extern "C" uint32_t verify_peer_enclave_trust(sgx_dh_session_enclave_identity_t* peer_enclave_identity)
{
    if(!peer_enclave_identity)
    {
        return INVALID_PARAMETER_ERROR;
    }
    if(peer_enclave_identity->isv_prod_id != 0 || !(peer_enclave_identity->attributes.flags & SGX_FLAGS_INITTED))
        // || peer_enclave_identity->attributes.xfrm !=3)// || peer_enclave_identity->mr_signer != xx //TODO: To be hardcoded with values to check
    {
        return ENCLAVE_TRUST_ERROR;
    }
    else
    {
        return SUCCESS;
    }
}


//Dispatcher function that calls the approriate enclave function based on the function id
//Each enclave can have its own way of dispatching the calls from other enclave
extern "C" uint32_t enclave_to_enclave_call_dispatcher(char* decrypted_data,
                                                       size_t decrypted_data_length,
                                                       char** resp_buffer,
                                                       size_t* resp_length)
{
    ms_in_msg_exchange_t *ms;
    uint32_t (*fn1)(ms_in_msg_exchange_t *ms, size_t, char**, size_t*);
    if(!decrypted_data || !resp_length)
    {
        return INVALID_PARAMETER_ERROR;
    }
    ms = (ms_in_msg_exchange_t *)decrypted_data;
    if(ms->target_fn_id >= func_table.num_funcs)
    {
        return INVALID_PARAMETER_ERROR;
    }
    fn1 = (uint32_t (*)(ms_in_msg_exchange_t*, size_t, char**, size_t*))func_table.table[ms->target_fn_id];
    return fn1(ms, decrypted_data_length, resp_buffer, resp_length);
}

//Operates on the input secret and generates the output secret
uint32_t get_message_exchange_response(uint32_t inp_secret_data)
{
    uint32_t secret_response;

    //User should use more complex encryption method to protect their secret, below is just a simple example
    secret_response = inp_secret_data & 0x11111111; 

    return secret_response;

}

//Generates the response from the request message
extern "C" uint32_t message_exchange_response_generator(char* decrypted_data,
                                              char** resp_buffer,
                                              size_t* resp_length)
{
    ms_in_msg_exchange_t *ms;
    uint32_t inp_secret_data;
    char* inp_really_secret_data = (char*) malloc(20);
    uint32_t out_secret_data;
    if(!decrypted_data || !resp_length)
    {
        return INVALID_PARAMETER_ERROR;
    }
    ms = (ms_in_msg_exchange_t *)decrypted_data;

    // if(umarshal_message_exchange_request(&inp_secret_data,ms) != SUCCESS)
    //     return ATTESTATION_ERROR;
    if(umarshal_message_exchange_request3(inp_really_secret_data,ms) != SUCCESS)
        return ATTESTATION_ERROR;
    ocall_print("\nENCLAVE1 RECEIVED MESSAGE: ");
    ocall_print(inp_really_secret_data);

    out_secret_data = get_message_exchange_response(inp_secret_data);

    if(marshal_message_exchange_response(resp_buffer, resp_length, out_secret_data) != SUCCESS)
        return MALLOC_ERROR;

    return SUCCESS;

}


static uint32_t e1_foo1(external_param_struct_t *p_struct_var)
{
    if(!p_struct_var)
    {
        return INVALID_PARAMETER_ERROR;
    }
    (p_struct_var->var1)++;
    (p_struct_var->var2)++;
    (p_struct_var->p_internal_struct->ivar1)++;
    (p_struct_var->p_internal_struct->ivar2)++;

    return (p_struct_var->var1 + p_struct_var->var2 + p_struct_var->p_internal_struct->ivar1 + p_struct_var->p_internal_struct->ivar2);
}

//Function which is executed on request from the source enclave
static uint32_t e1_foo1_wrapper(ms_in_msg_exchange_t *ms,
                    size_t param_lenth,
                    char** resp_buffer,
                    size_t* resp_length)
{
    UNUSED(param_lenth);

    uint32_t ret;
    size_t len_data, len_ptr_data;
    external_param_struct_t *p_struct_var;
    internal_param_struct_t internal_struct_var;

    if(!ms || !resp_length)
    {
        return INVALID_PARAMETER_ERROR;
    }

    p_struct_var = (external_param_struct_t*)malloc(sizeof(external_param_struct_t));
    if(!p_struct_var)
        return MALLOC_ERROR;

    p_struct_var->p_internal_struct = &internal_struct_var;

    if(unmarshal_input_parameters_e1_foo1(p_struct_var, ms) != SUCCESS)//can use the stack
    {
        SAFE_FREE(p_struct_var);
        return ATTESTATION_ERROR;
    }

    ret = e1_foo1(p_struct_var);

    len_data = sizeof(external_param_struct_t) - sizeof(p_struct_var->p_internal_struct);
    len_ptr_data = sizeof(internal_struct_var);

    if(marshal_retval_and_output_parameters_e1_foo1(resp_buffer, resp_length, ret, p_struct_var, len_data, len_ptr_data) != SUCCESS)
    {
        SAFE_FREE(p_struct_var);
        return MALLOC_ERROR;
    }
    SAFE_FREE(p_struct_var);
    return SUCCESS;
}

//PASSWORD MANAGER CODE BELOW-----------------------------------------

const unsigned MAX_PASSWORD_SIZE = 1024; 

//NOTE: if you run into bus error, edit enclave.edl and modify the parameter lengths for strings

char* password; //main password for entire keystore
int numPasswords = 0;

uint8_t buffer[1024]; //first 12 bytes are random bytes generated by read_rand for encryption, rest bytes are used to store temporary stuff for aes-encryption

struct KeyStoreBank
{
	char* website;
	char* password;
	KeyStoreBank* next;
};

KeyStoreBank* firstKey = (KeyStoreBank*) malloc(sizeof(struct KeyStoreBank));
KeyStoreBank* currentKey = firstKey;

void encrypt(char* str) {
	while (*str != '\0') {
		*str = *str + 1;
		str++;
	}
}

void decrypt(char* str) {
	while (*str != '\0') {
		*str = *str - 1;
		str++;
	}
}

int create_keystore(char* main_password) {
	size_t password_len = strlen(main_password);
	password = (char*) malloc(sizeof(char) + password_len + 1);
	if (password == NULL) {
		abort();
	}
	strncpy(password, main_password, password_len);
    password[password_len] = '\0';
	firstKey->next=NULL;
	return 0;


}

int add_password(char* website, char* password) {
	size_t password_len = strlen(password);
	size_t website_len = strlen(website);
    if (password_len >= MAX_PASSWORD_SIZE || website_len >= MAX_PASSWORD_SIZE) {
        // fail if password greater than a particular size.
        return -1;
    }
    currentKey->password = (char*) malloc(sizeof(char) * password_len + 1);
    currentKey->website = (char*) malloc(sizeof(char) * website_len + 1);
    if (currentKey->password == NULL) {
    	abort(); //out of memory
    }
    strncpy(currentKey->password, password, password_len);
    strncpy(currentKey->website, website, website_len);    
    currentKey->password[password_len] = '\0';
    currentKey->website[website_len] = '\0';

    KeyStoreBank* newKey = (KeyStoreBank*) malloc(sizeof(struct KeyStoreBank));
    currentKey->next = newKey;
    currentKey = newKey;
    currentKey->next = NULL;
    numPasswords++;

    // return value = 0 means success.
    return 0;

}

int get_password(char* website, char* returnstr, char* verification_password) {
    ocall_print("Returning Password\n");
    size_t website_len = strlen(website);

    if (strcmp(verification_password, password) != 0) {
    	*returnstr = '\0';
    	return -1;
    }

    KeyStoreBank* iterator = firstKey;
    while (iterator != NULL && iterator->next != NULL && strcmp(website, iterator->website) != 0) {
    	iterator = iterator->next;



    }
    if (iterator == NULL || iterator->next == NULL) {
    	*returnstr = '\0';
    	return -1;
    }
    strncpy(returnstr, iterator->password, strlen(iterator->password));
    returnstr[strlen(iterator->password)]= '\0';
    unsigned char var[3] = "hi";
    //TODO remove this readrand code

    sgx_read_rand(var, 2);

    const uint8_t* passwd = (const uint8_t*) "password";
    size_t passwdlen = 8;
    const uint8_t * salt = (const uint8_t*) "salt";
    size_t saltlen = 4;
    uint8_t * buf = (uint8_t *) malloc(1024 * sizeof(char));
    size_t buflen = 1024;
    uint64_t N = 8;
    uint32_t _r = 30;
    uint32_t _p = 20;


    if (buf == NULL) {
        ocall_print("Buffer Error\n");
    } else {
        crypto_scrypt(passwd, passwdlen, salt, saltlen, N, _r, _p, buf, buflen);
    }

   // sgx_rijndael128GCM_encrypt()

    return 0;
}


char* itoa(int val, int base){
	
	static char buf[32] = {0};
	
	int i = 30;
	
	for(; val && i ; --i, val /= base)
	
		buf[i] = "0123456789abcdef"[val % base];
	
	return &buf[i+1];
	
}

char* string_integer_concat(char* str, int a) {
	char* str2 = itoa(a, 10);
	int len1 = strlen(str);
	int len2 = strlen(str2);
	char* final = (char*) malloc(len1 + len2 + 1);
	char* iterator = final;
	

	for (int i = 0; i < len1; i++) {
		*iterator = *str;
		iterator++;
		str++;
	}
	for (int i = 0; i < len2; i++) {
		*iterator = *str2;
		iterator++;
		str2++;
	} 
	*iterator = '\0';
	return final;
}

void dumb_mem_cpy(void* dst, void* toCopy, int size) {
	char* iterator1 = (char*) dst;
	char* iterator2 = (char*) toCopy;
	for (int i = 0; i < size; i++) {
		*iterator1 = *iterator2;
		iterator1++;
		iterator2++;
	}

}

int encrypt_and_serialize_key_store(void* p_dst) {

	static sgx_aes_ctr_128bit_key_t g_region_key;
	uint8_t key[16] = "abshsydgsvsgshs";
	//TODO make this key a pbkdf of masterpassword, and use that in deserialization as well 
	memcpy(g_region_key, key, sizeof(key));


	uint8_t blob[1024] = { 0 };
	if(sgx_read_rand(blob, 12))
		return -1;

	serialize_key_store(p_dst);
	uint8_t* output = (uint8_t*) malloc(binn_size(p_dst));
	int sizeP = binn_size(p_dst);


	sgx_status_t status = sgx_rijndael128GCM_encrypt(&g_region_key, (const uint8_t*) p_dst, binn_size(p_dst), (uint8_t*) output, blob, 12, NULL, 0, (sgx_aes_gcm_128bit_tag_t *) (blob + 12));
	

	memcpy(buffer, blob, 1024); //save blob for decryption purposes


	if (status != SGX_SUCCESS) {
		ocall_print("dude it failed");
		return -1;
	}


	memcpy(p_dst, output, sizeP);

	return 0;



}

int serialize_key_store(void* p_dst) {

	binn* obj = binn_object();
	KeyStoreBank* key = firstKey;
	int i = 0;
	
	while (key->next != NULL) {
		binn_object_set_str(obj, string_integer_concat("website", i), key->website);
		binn_object_set_str(obj, string_integer_concat("password", i), key->password);
		key = key->next;
		i++;
	}
	

	memcpy(p_dst, binn_ptr(obj), binn_size(obj));

	binn_free(obj);

	return 0;



}



int decrypt_and_set_key_store(void* key_store) {
	
	//need to call free

	//todo: figure out buffer serializing over encalve close, and somehow need to transmit sizeP

	
	static sgx_aes_ctr_128bit_key_t g_region_key;
	uint8_t key[16] = "abshsydgsvsgshs";
	memcpy(g_region_key, key, sizeof(key));
	int sizeP = 35;
	uint8_t* decrypted_output = (uint8_t*) malloc(sizeP);


	sgx_status_t status = sgx_rijndael128GCM_decrypt(&g_region_key, (const uint8_t*) key_store, sizeP, (uint8_t*) decrypted_output, buffer, 12, NULL, 0, (sgx_aes_gcm_128bit_tag_t *) (buffer + 12));


	if (status != SGX_SUCCESS) {
		ocall_print("Failed");
		return -1;
	}

	key_store = (void*) decrypted_output;

	

	firstKey = (KeyStoreBank*) malloc(sizeof(struct KeyStoreBank));
    currentKey = firstKey;
    firstKey->next=NULL;
    numPasswords = 0;


    char* temp = binn_object_str(key_store, string_integer_concat("website", 0));
    int i = 0;
    while (temp != NULL) {

    	char* website = binn_object_str(key_store, string_integer_concat("website", i));
    	char* password = binn_object_str(key_store, string_integer_concat("password", i));
    	ocall_print(website);
    	ocall_print(password);
    	
    	add_password(website,password);
    	i++;
    	
    	temp = binn_object_str(key_store, string_integer_concat("website", i));
    }


}



