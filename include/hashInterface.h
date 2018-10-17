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
	H_MD5
};



	
/*
����: ����hash
����:
	hashID: ժҪ�㷨
		00 : SHA-1
		01 : SHA-224
		02 : SHA-256
		03 : SHA-384
		04 : SHA-512
		05:  MD5
	data:��hash ����
	datalen: ���ݳ���
	digest: hash ֵ
����:
	>0 hash ֵ�ֽ���
	<0 ʧ��
*/

int DigestWithOpenssl(int hashID,unsigned char *data,int datalen,unsigned char *digest);




/*
����: ʹ��PBKDF2 ��ʽ��ɢ��Կ 
����:
	hashID: ժҪ�㷨
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
���:
	key: ��ɢ�õ���key

����:
	0 �ɹ�
	<0 ʧ��
PKCS5_PBKDF2_HMAC() and PBKCS5_PBKDF2_HMAC_SHA1() return 1 on success or 0 on error.

#include <openssl/evp.h>

int PKCS5_PBKDF2_HMAC(const char *pass, int passlen,
const unsigned char *salt, int saltlen, int iter,
const EVP_MD *digest,
int keylen, unsigned char *out);

 */

int PBKDF2WithOpenssl(int hashID,unsigned char *msg,int msglen,unsigned char *salt,int saltlen,int iter,int keylen,unsigned char *key);

#ifdef __cplusplus
}
#endif


#endif




