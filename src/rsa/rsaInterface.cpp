#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/des.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/pkcs12.h>

#ifdef WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

#include "str.h"
#include "rsa.h"
#include "rsaInterface.h"


//生成RSA密钥
int RSAGenDerKey(int bits,unsigned long  e,unsigned char *pk,int *pklen,unsigned char *vk,int *vklen)
{
    return GenRSADerKey(bits,e,pk,pklen,vk,vklen);
}



//私钥 PKCS1 加密
int VKEncPKCS1(unsigned char *vk,int vklen,unsigned char *plainTxt,int plainTxtLen,unsigned char *encTxt)
{
	return RSAVKEnc(vk,vklen,plainTxt,plainTxtLen,1,encTxt);
}

//私钥加密(不填充)
int VKEnc(unsigned char *vk,int vklen,unsigned char *plainTxt,int plainTxtLen,unsigned char *encTxt)
{
	return RSAVKEnc(vk,vklen,plainTxt,plainTxtLen,0,encTxt);
}


//公钥PKCS1解密
int PKDecPKCS1(unsigned char *pk,int pklen,unsigned char *cryptTxt,int cryptTxtLen,unsigned char *plainTxt)
{
	return RSAPKDec(cryptTxt,cryptTxtLen,pk,pklen,1,plainTxt);
}


//公钥解密(不填充)
int PKDec(unsigned char *pk,int pklen,unsigned char *cryptTxt,int cryptTxtLen,unsigned char *plainTxt)
{
	return RSAPKDec(cryptTxt,cryptTxtLen,pk,pklen,0,plainTxt);
}


//公钥加密 PKCS1
int PKEncPKCS1(unsigned char *pk,int pklen,unsigned char *plainTxt,int plainTxtLen,unsigned char *cryptTxt)
{
	return RSAPKEnc(plainTxt,plainTxtLen,pk,pklen,1,cryptTxt);
}

//公钥加密(不填充)
int PKEnc(unsigned char *pk,int pklen,unsigned char *plainTxt,int plainTxtLen,unsigned char *cryptTxt)
{
	return RSAPKEnc(plainTxt,plainTxtLen,pk,pklen,0,cryptTxt);
}

//私钥解密 PKCS1
int VKDecPKCS1(unsigned char *vk,int vklen,unsigned char *cryptTxt,int cryptTxtLen,unsigned char *plainTxt)
{
	return RSAVKDec(cryptTxt,cryptTxtLen,vk,vklen,1,plainTxt);
}

//私钥解密(不填充)
int VKDec(unsigned char *vk,int vklen,unsigned char *cryptTxt,int cryptTxtLen,unsigned char *plainTxt)
{
	return RSAVKDec(cryptTxt,cryptTxtLen,vk,vklen,0,plainTxt);
}


/*
功能: 用口令加密RSA私钥明文得到私钥密文
输入:
	dervk: der 格式的私钥明文
	vklen:私钥明文长度
	passwd: 私钥保护口令
输出:
	vkbypasswd: 私钥密文
返回:
	>0 私钥密文的长度
	<0 失败
*/

int EncryptDerVkBypassword(unsigned char *dervk,int vklen,char *passwd,char *vkbypasswd)
{
	int ret = 0;
	EVP_PKEY    *pkey = NULL;
	long 		inl=0;
	char		buf[8192+1]={0};
	unsigned char *const_buf = NULL;
	BIO *pbio = NULL;
	pkey=EVP_PKEY_new();
	const_buf = dervk;
	inl = vklen ;
	if(d2i_PrivateKey(EVP_PKEY_RSA,&pkey,(const unsigned char **)&const_buf,inl) == NULL )
	{
		EVP_PKEY_free(pkey);
		printf("in UnionEncryptRSAVkeyByPwd d2i_PrivateKey failed \n");
		return -1;
	}

	pbio = BIO_new(BIO_s_mem());
	if (pbio == NULL)
	{
		EVP_PKEY_free(pkey);
		printf("in UnionEncryptRSAVkeyByPwd BIO_new(BIO_s_mem) failed!\n");
		return -2;
	}
	if(!PEM_write_bio_PrivateKey(pbio,pkey,EVP_des_ede3_cbc(),
		(unsigned char*)passwd,strlen(passwd),0,NULL)) 
	{
		BIO_free(pbio);
		EVP_PKEY_free(pkey);
		return -3;
	}
	ret = BIO_read(pbio,buf,sizeof(buf));
	memcpy(vkbypasswd,buf,ret);

	BIO_free(pbio);
	pbio = NULL;
	EVP_PKEY_free(pkey);
	pkey = NULL;
	return ret;
}



/*
功能:从私钥密文获取私钥明文
输入:
	vkbypasswd: 私钥密文
	vklen:私钥密文长度
	passwd: 私钥保护口令
输出:
	derVK: DER格式的私钥
返回:
	>0 der格式私钥的长度
	<0 失败
*/

int DecryptPEMVk2Der(char *vkbypasswd,int vklen,char *passwd,unsigned char *derVK)
{
	BIO *pbio = NULL;
	int len = 0;
	unsigned char *buf = NULL;
	char buffer[4096]={0};
	EVP_PKEY	*pKey = NULL;
	int ret = 0;	
	if ((vkbypasswd == NULL  || vklen <0 || passwd == NULL || derVK == NULL))
	{
		printf("in DecryptPEMVk2Der::para err .\n");
		return -1;
	}


	pbio = BIO_new(BIO_s_mem());
	if (pbio == NULL)
	{
		
		printf("DecryptPEMVk2Der BIO_new(BIO_s_mem) failed!\n");
		return -2;
	}
	ret = BIO_write(pbio,vkbypasswd,vklen);
	
	pKey = PEM_read_bio_PrivateKey(pbio,NULL,0,(unsigned char*)passwd);
	if(pKey == NULL) {
		printf("in DecryptPEMVk2Der::PEM_read_bio_PrivateKey failed .\n");
		BIO_free(pbio);
		return -3;
	}

	BIO_free(pbio);
	pbio = NULL;

	len = i2d_PrivateKey(pKey,&buf);
	if(len<0)
	{
		printf("in DecryptPEMVk2Der::i2d_PrivateKey failed \n");
		EVP_PKEY_free(pKey);
		free(buf);
		return -4;
	}
	memcpy(derVK,buf,len);
	EVP_PKEY_free(pKey);
	free(buf);
	return len;
}