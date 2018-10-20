#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>


#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#include "openssl_init.h"
#include "hashInterface.h"


/*
功能: 计算hash
输入:
	hashID: 摘要算法
	00 : SHA-1
	01 : SHA-224
	02 : SHA-256
	03 : SHA-384
	04 : SHA-512
	05:  MD5
	data:待hash 数据
	datalen: 数据长度
	digest: hash 值
返回:
	>0 hash 值字节数
	<0 失败
*/

int DigestWithOpenssl(int hashID,unsigned char *data,int datalen,unsigned char *digest)
{
	const EVP_MD *md = NULL;
	unsigned char mdout[1024]={0};
	int len = 0;
	int ret = 0;
	switch(hashID)
	{
	case H_SHA1:
		md = EVP_sha1();
		break;
	case H_SHA224:
		md = EVP_sha224();
		break;
	case H_SHA256:
		md = EVP_sha256();
		break;
	case H_SHA384:
		md = EVP_sha384();
		break;
	case H_SHA512:
		md = EVP_sha512();
		break;
	case H_MD5:
		md = EVP_md5();
		break;
	default:
		printf("not support hashID[%d]\n",hashID);
		return -1;
	}
	 memset(mdout,0,sizeof(mdout));
	 ret = EVP_Digest(data,datalen,mdout,(unsigned int*)&len,md,NULL);
	 if (!ret)
	 {
		 printf("in DigestWithOpenssl::EVP_Digest failed at %s %d\n",__FILE__,__LINE__);
		 return -2;
	 }
	 memcpy(digest,mdout,len);
	 return len;
}





 /*
功能: 使用PBKDF2 方式离散密钥 
输入:
	hashID: 摘要算法
	00 : SHA-1
	01 : SHA-224
	02 : SHA-256
	03 : SHA-384
	04 : SHA-512
	05:  MD5
	msg: the message to hash
	msglen: msglen len
	salt: salt
	saltlen: saltlen
	iter: iter
	keylen: length of the hash to generate
输出:
	key: 离散得到的key

返回:
	0 成功
	<0 失败
PKCS5_PBKDF2_HMAC() and PBKCS5_PBKDF2_HMAC_SHA1() return 1 on success or 0 on error.

#include <openssl/evp.h>

int PKCS5_PBKDF2_HMAC(const char *pass, int passlen,
const unsigned char *salt, int saltlen, int iter,
const EVP_MD *digest,
int keylen, unsigned char *out);

 */

 int PBKDF2WithOpenssl(int hashID,unsigned char *msg,int msglen,unsigned char *salt,int saltlen,int iter,int keylen,unsigned char *key)
 {
	 int ret = 0;
	 const EVP_MD      *md = NULL;
	 unsigned char buf[256]={0};
	 switch(hashID)
	 {
	 case H_SHA1:
		 md = EVP_sha1();
		 break;
	 case H_SHA224:
		 md = EVP_sha224();
		 break;
	 case H_SHA256:
		 md = EVP_sha256();
		 break;
	 case H_SHA384:
		 md = EVP_sha384();
		 break;
	 case H_SHA512:
		 md = EVP_sha512();
		 break;
	 case H_MD5:
		 md = EVP_md5();
		 break;
	 default:
		 printf("in PBKDF2::not support hashID[%d]\n",hashID);
		 return -1;
	 }
	 if ((ret = PKCS5_PBKDF2_HMAC((const char*)msg,msglen,salt,saltlen,iter,md,keylen,buf))!=1)
	 {
		 printf("in PBKDF2::PKCS5_PBKDF2_HMAC failed \n");
		 return -2;
	 }
	 memcpy(key,buf,keylen);
	 return keylen;
 }


 int HMACWithOpenssl(int hashID,unsigned char *key,int keylen,unsigned char *data,int datalen,unsigned char *mac)
 {

	 int ret = 0;
	 const EVP_MD      *md = NULL;
	 unsigned char buf[256]={0};
	 unsigned int len = 0;
	 switch(hashID)
	 {
	 case H_SHA1:
		 md = EVP_sha1();
		 break;
	 case H_SHA224:
		 md = EVP_sha224();
		 break;
	 case H_SHA256:
		 md = EVP_sha256();
		 break;
	 case H_SHA384:
		 md = EVP_sha384();
		 break;
	 case H_SHA512:
		 md = EVP_sha512();
		 break;
	 case H_MD5:
		 md = EVP_md5();
		 break;
	 default:
		 printf("in HMACWithOpenssl::not support hashID[%d]\n",hashID);
		 return -1;
	 }
	 HMAC_CTX ctx;
	 HMAC_CTX_init(&ctx);
	 HMAC_Init(&ctx,key,keylen,md);
	 HMAC_Update(&ctx,data,datalen);
	 HMAC_Final(&ctx,buf,&len);
	 HMAC_CTX_cleanup(&ctx);
	 memcpy(mac,buf,len);
	 return len;
 }
