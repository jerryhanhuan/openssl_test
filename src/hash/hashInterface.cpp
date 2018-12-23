#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>


#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#include "openssl_init.h"
#include "hashInterface.h"
#include "sha3.h"
#include "merkle_tree.h"
#include "str.h"

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


int SHA3(int hashID,unsigned char *in,int ilen,unsigned char *out)
{

	sha3_ctx_t sha3;
	int hlen = 0;
	switch(hashID)
	{
		case H_SHA3_224:
			hlen = 224/8;
			break;
		case H_SHA3_256:
			hlen = 256/8;
			break;
		case H_SHA3_384:
			hlen = 384/8;
			break;
		case H_SHA3_512:
			hlen = 512/8;
			break;
		default:
			printf("not support hashID[%d]\n",hashID);
			return -1;
	}
	 sha3_init(&sha3, hlen);
	 sha3_update(&sha3, in, ilen);
     sha3_final(out, &sha3);
	 return hlen;
}

int keccak(int hashID,unsigned char *in,int ilen,unsigned char *out)
{
	sha3_ctx_t sha3;
	int hlen = 0;
	switch(hashID)
	{
		case H_KECCAK_224:
			hlen = 224/8;
			break;
		case H_KECCAK_256:
			hlen = 256/8;
			break;
		case H_KECCAK_384:
			hlen = 384/8;
			break;
		case H_KECCAK_512:
			hlen = 512/8;
			break;
		default:
			printf("not support hashID[%d]\n",hashID);
			return -1;
	}
	 sha3_init(&sha3, hlen);
	 sha3_update(&sha3, in, ilen);
     Keccak_final(out, &sha3);
	 return hlen;
}



int MerkleHash2()
{

	char *node1 = "FB0E438520806E2401893B0546EAA52EDE7F6E577F9319EF9EEC41AA334CCA7C";
	char *node2 = "10A8943CFE4C83D8D85EC23D381EF23EEE67D455D5DAE4CA472D9509BB17F245";
	char *node3 = "DE5A6F78116ECA62D7FC5CE159D23AE6B889B365A1739AD2CF36F925A140D0CC";
	char *node4 = "30CA65D5DA355227C97FF836C9C6719AF9D3835FC6BC72BDDC50EEECC1BB2B25";
	char *node5 = "53F8E3DE79EA16B1BC180A2A8DC49B23ADAF64B2C270FFA56F1C059E99CA4FA9";
	unsigned char hash[100][32]={0};

	aschex_to_bcdhex(node1,strlen(node1),(char*)hash[0]);
	aschex_to_bcdhex(node2,strlen(node2),(char*)hash[1]);
	aschex_to_bcdhex(node3,strlen(node3),(char*)hash[2]);
	aschex_to_bcdhex(node4,strlen(node4),(char*)hash[3]);
	aschex_to_bcdhex(node5,strlen(node5),(char*)hash[4]);

	unsigned char result[32]={0};
	MerkleHash(hash,5,result);

	char resultHex[65]={0};
	bcdhex_to_aschex((char*)result,32,resultHex);
	printf("resultHex::[%s]\n",resultHex);
	return 0;

}