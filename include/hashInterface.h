#ifndef __HASH_INTERFACE_H
#define __HASH_INTERFACE_H

#ifdef __cplusplus
extern "C"{
#endif


enum{
	H_SHA1,
	H_SHA224,
	H_SHA256,
	H_SHA384,
	H_SHA512,
	H_MD5,
	H_MDC2,
	H_SHA3_224,
	H_SHA3_256,
	H_SHA3_384,
	H_SHA3_512,
	H_KECCAK_224,
	H_KECCAK_256,
	H_KECCAK_384,
	H_KECCAK_512
};


	
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
	digest: hash 结果
返回:
	>0 hash 值字节数
	<0 失败
*/

int DigestWithOpenssl(int hashID,unsigned char *data,int datalen,unsigned char *digest);




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

int PBKDF2WithOpenssl(int hashID,unsigned char *msg,int msglen,unsigned char *salt,int saltlen,int iter,int keylen,unsigned char *key);



 int HMACWithOpenssl(int hashID,unsigned char *key,int keylen,unsigned char *data,int datalen,unsigned char *mac);




int SHA3(int hashID,unsigned char *in,int ilen,unsigned char *out);

int keccak(int hashID,unsigned char *in,int ilen,unsigned char *out);







#ifdef __cplusplus
}
#endif


#endif





