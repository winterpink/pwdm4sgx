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


// App.cpp : 该部分定义控制台入口点信息，即输入命令
#include <stdio.h>
#include <map>
#include "../Enclave1/Enclave1_u.h"
#include "../Enclave2/Enclave2_u.h"
#include "sgx_eid.h"
#include "sgx_urts.h"
#define __STDC_FORMAT_MACROS
#include <inttypes.h>


#define UNUSED(val) (void)(val) //没有任何意义，单纯用来占位，防止编译的时候提示未使用的变量
#define TCHAR   char
#define _TCHAR  char
#define _T(str) str
#define scanf_s scanf
#define _tmain  main

//使用map来存储安全飞地的id信息并设置全局变量
extern std::map<sgx_enclave_id_t, uint32_t>g_enclave_id_map;

//初始化飞地id
sgx_enclave_id_t e1_enclave_id = 0;
sgx_enclave_id_t e2_enclave_id = 0;

//指定生成的库系统动态链接库路径
#define ENCLAVE1_PATH "libenclave1.so"
#define ENCLAVE2_PATH "libenclave2.so"

//每输出一个字符串之后输出一个换行符
void ocall_print(const char* str) {
    printf("%s\n", str);
}

//加载安全飞地
uint32_t load_enclaves()
{
    uint32_t enclave_temp_no;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    enclave_temp_no = 0;

    ret = sgx_create_enclave(ENCLAVE1_PATH, SGX_DEBUG_FLAG, NULL, NULL, &e1_enclave_id, NULL);
    if (ret != SGX_SUCCESS) {
                return ret;
    }

    enclave_temp_no++;
    g_enclave_id_map.insert(std::pair<sgx_enclave_id_t, uint32_t>(e1_enclave_id, enclave_temp_no));

    ret = sgx_create_enclave(ENCLAVE2_PATH, SGX_DEBUG_FLAG, NULL, NULL, &e2_enclave_id, NULL);
    if (ret != SGX_SUCCESS) {
                return ret;
    }

    enclave_temp_no++;
    g_enclave_id_map.insert(std::pair<sgx_enclave_id_t, uint32_t>(e2_enclave_id, enclave_temp_no));


    return SGX_SUCCESS;
}

//输出主函数
int _tmain(int argc, _TCHAR* argv[])
{
    uint32_t ret_status;
    sgx_status_t status;

    UNUSED(argc);
    UNUSED(argv);

    //如果加载状态失败，输出
    if(load_enclaves() != SGX_SUCCESS)
    {
        printf("\n安全飞地无法加载");
    }
    
    //输出可使用的飞地id
    printf("\n可使用的安全飞地：");
    printf("\nsrc:Enclave1 - EnclaveID %" PRIx64, e1_enclave_id);
    printf("\ndes:Enclave2 - EnclaveID %" PRIx64, e2_enclave_id);
    printf("\n");


    printf("欢迎使用SGX密码管理系统\n");
    printf("输入 \"help\"\n");


    while (true)
    {

        // 这里使用std::string
        // 为每个字符串命令分配长度
        char strCommand[100];

        char str1[100];
        char str2[100];
        char str3[100];
        char str4[100];
        int i;
        void *encrypt = malloc(100);

        printf("请输入操作指令: ");

        // std::getline (std::cin, command)
        
        // 这是scanf中的正则用法
        scanf("%[^\n]%*c", strCommand);
        // strtok分解成单个字符串
        char* split = strtok(strCommand, " ");
        //复制给str1
        strcpy(str1, split);

        if (strcmp(str1, "help") == 0) {
            printf("可使用的指令：\n");
            printf("create MasterPassword\n");
            printf("add Website WebsitePassword\n");
            printf("get Website MasterPassword\n");
            printf("send ping\n");
            printf("quit\n");

        } 
        // 比较str1=quit结束程序
        else if (strcmp(str1, "quit") == 0) 
        {
            break;
        } 
        else if (strcmp(str1, "create") == 0)
        {

            printf("正在建立并初始化密码库...\n");
            split = strtok(NULL, " ");
            strcpy(str2, split); //str2 = main keystore password
            int create_keystore_return;
            sgx_status_t status = Enclave1_create_keystore(e1_enclave_id, &create_keystore_return, str2);
        }
        else if (strcmp(str1, "add") == 0)
        {
            printf("正在添加密码...\n");

            int add_password_return;
            split = strtok(NULL, " ");
            strcpy(str2, split);
            split = strtok(NULL, " ");
            strcpy(str3, split);
            //str2 = website
            //str3 = password

            sgx_status_t status2 = Enclave1_add_password(e1_enclave_id, &add_password_return, str2, str3);
            printf("密码添加成功: %u\n", add_password_return);
        }
        else if (strcmp(str1, "get") == 0)
        {
            printf("正在获取密码...\n");

            char get_password_return_str[16];
            int get_password_return;
            split = strtok(NULL, " ");
            strcpy(str2, split);
            split = strtok(NULL, " ");
            strcpy(str3, split);
            //str2 = website
            //str3 = main keystore password

            sgx_status_t status3 = Enclave1_get_password(e1_enclave_id, &get_password_return, str2, get_password_return_str, str3);
            printf("密码查询成功: %u\n", get_password_return);
            printf("在buffer中找到以下密码: %s\n", get_password_return_str);
        } else if (strcmp(str1, "send") == 0) {

            int get_password_return;
            split = strtok(NULL, " ");
            strcpy(str2, split);


            //以下部分为两个安全飞地进行本地认证的输出信息，每一次测试都需要双向认证
            status = Enclave1_test_create_session(e1_enclave_id, &ret_status, e1_enclave_id, e2_enclave_id);
            if (status!=SGX_SUCCESS)
            {
                printf("Enclave1_test_create_session Ecall failed: Error code is %x", status);
                break;
            }
            else
            {
                if(ret_status==0)
                {
                    printf("\nSecure Channel Establishment between Source (E1) and Destination (E2) Enclaves successful!");
                }
                else
                {
                    printf("\nSession establishment and key exchange failure between Source (E1) and Destination (E2): Error code is %x", ret_status);
                    break;
                }
            }

            //Test message exchange between Enclave1(Source) and Enclave2(Destination)
            status = Enclave1_test_message_exchange(e1_enclave_id, &ret_status, e1_enclave_id, e2_enclave_id, str2, strlen(str2));
            if (status!=SGX_SUCCESS)
            {
                printf("Enclave1_test_message_exchange Ecall failed: Error code is %x", status);
                break;
            }
            else
            {
                if(ret_status==0)
                {
                    printf("\nMessage Exchange between Source (E1) and Destination (E2) Enclaves successful!");
                }
                else
                {
                    printf("\nMessage Exchange failure between Source (E1) and Destination (E2): Error code is %x", ret_status);
                    break;
                }
            }

            
        

            //Test Closing Session between Enclave1(Source) and Enclave2(Destination)
            status = Enclave1_test_close_session(e1_enclave_id, &ret_status, e1_enclave_id, e2_enclave_id);
            if (status!=SGX_SUCCESS)
            {
                printf("Enclave1_test_close_session Ecall failed: Error code is %x", status);
                break;
            }
            else
            {
                if(ret_status==0)
                {
                    printf("\nClose Session between Source (E1) and Destination (E2) Enclaves successful!");
                }
                else
                {
                    printf("\nClose session failure between Source (E1) and Destination (E2): Error code is %x", ret_status);
                    break;
                }
            }
            printf("\n");

            if (strcmp(str2, "ping") == 0) {

                printf("\n");
                printf("\n");
                printf("ENCLAVE2 Sending Pong---------\n");
                //Test Create session between Enclave2(Source) and Enclave1(Destination)
                status = Enclave2_test_create_session(e2_enclave_id, &ret_status, e2_enclave_id, e1_enclave_id);
                if (status!=SGX_SUCCESS)
                {
                    printf("Enclave2_test_create_session Ecall failed: Error code is %x", status);
                    break;
                }
                else
                {
                    if(ret_status==0)
                    {
                        printf("\n\nSecure Channel Establishment between Source (E2) and Destination (E1) Enclaves successful!");
                    }
                    else
                    {
                        printf("\nSession establishment and key exchange failure between Source (E2) and Destination (E1): Error code is %x", ret_status);
                        break;
                    }
                }



                status = Enclave2_test_message_exchange(e2_enclave_id, &ret_status, e2_enclave_id, e1_enclave_id, "pong", 4);
                if (status!=SGX_SUCCESS)
                {
                    printf("Enclave2_test_message_exchange Ecall failed: Error code is %x", status);
                    break;
                }
                else
                {
                    if(ret_status==0)
                    {
                        printf("\n\nMessage Exchange between Source (E2) and Destination (E1) Enclaves successful!");
                    }
                    else
                    {
                        printf("\n\nMessage Exchange failure between Source (E2) and Destination (E1): Error code is %x", ret_status);
                        break;
                    }
                }

                //Test Closing Session between Enclave1(Source) and Enclave2(Destination)
                status = Enclave2_test_close_session(e2_enclave_id, &ret_status, e2_enclave_id, e1_enclave_id);
                if (status!=SGX_SUCCESS)
                {
                    printf("Enclave2_test_close_session Ecall failed: Error code is %x", status);
                    break;
                }
                else
                {
                    if(ret_status==0)
                    {
                        printf("\n\nClose Session between Source (E2) and Destination (E1) Enclaves successful!");
                    }
                    else
                    {
                        printf("\n\nClose session failure between Source (E2) and Destination (E1): Error code is %x", ret_status);
                        break;
                    }
                }
                printf("\n");


            }

        }
        else if (strcmp(str1, "encrypt") == 0)
        {
            //Serializes keystone (all data along with masterpassword) and saves to file
            printf("Serializing Keystore");

            int encrypt_return;
            //使用scrypt派生密钥加密
            FILE *fp = fopen("encrypt.txt", "w+");

            sgx_status_t status4 = Enclave1_encrypt_and_serialize_key_store(e1_enclave_id, &encrypt_return, encrypt);
            fprintf(fp, "%s", encrypt);
            fclose(fp);
            printf("serialize_key_store returned: %u\n", encrypt_return);
            printf("serialize_key_store string: %s\n", (char *)encrypt);
        }
        else if (strcmp(str1, "decrypt") == 0)
        {
            printf("Decrypting and Setting Keystore");

            int encrypt_return;
            // 该部分按需使用，这部分是用来处理派生密钥错误信息的
            // size_t nread;

            // FILE *file = fopen("encrypt.txt", "r");
            // if (file) {
            //     while ((nread = fread(encrypt, 1, sizeof encrypt, file)) > 0)
            //         fwrite(encrypt, 1, nread, stdout);
            //     if (ferror(file)) {
            //         /* deal with error */
            //     }
            //     fclose(file);
            // }
            printf("encrypted string %s", encrypt);
            sgx_status_t status5 = Enclave1_decrypt_and_set_key_store(e1_enclave_id, &encrypt_return, encrypt);
        }
    }


    // 销毁所有安全飞地
    sgx_destroy_enclave(e1_enclave_id);
    sgx_destroy_enclave(e2_enclave_id);

    return 0;
}
