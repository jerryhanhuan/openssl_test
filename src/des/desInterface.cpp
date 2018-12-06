
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/des.h>
#include "desInterface.h"


int TDESEncryptWithECB(unsigned char *key, int keylen,unsigned char *data,int datalen,unsigned char *outdata)
{

    int ret = 0;
    DES_key_schedule ks1, ks2, ks3;
    unsigned char lk[8]={0};
    unsigned char mk[8]={0};
    unsigned char rk[8]={0};
    int i = 0;
    memcpy(lk,key,8);
    memcpy(mk,key+8,8);
    memcpy(rk,key+16,8);
    DES_set_key_unchecked((const_DES_cblock*)lk, &ks1);  
    DES_set_key_unchecked((const_DES_cblock*)mk, &ks2);  
    DES_set_key_unchecked((const_DES_cblock*)rk, &ks3);  
	
    for(i=0;i<datalen;i+=8)
    {
         DES_ecb3_encrypt((const_DES_cblock*)(data+i), (DES_cblock *)(outdata+i), &ks1, &ks2, &ks3, DES_ENCRYPT);
    }
    return datalen;
}


int TDESDecryptWithECB(unsigned char *key, int keylen,unsigned char *data,int datalen,unsigned char *outdata)
{
	int ret = 0;
    DES_key_schedule ks1, ks2, ks3;
    unsigned char lk[8]={0};
    unsigned char mk[8]={0};
    unsigned char rk[8]={0};
    int i = 0;
    memcpy(lk,key,8);
    memcpy(mk,key+8,8);
    memcpy(rk,key+16,8);
    DES_set_key_unchecked((const_DES_cblock*)lk, &ks1);  
    DES_set_key_unchecked((const_DES_cblock*)mk, &ks2);  
    DES_set_key_unchecked((const_DES_cblock*)rk, &ks3);  
    for(i=0;i<datalen;i+=8)
    {
         DES_ecb3_encrypt((const_DES_cblock*)(data+i), (DES_cblock *)(outdata+i), &ks1, &ks2, &ks3, DES_DECRYPT);
    }
    return datalen;
}









