#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#ifdef WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

#include <openssl/rsa.h>
#include <openssl/pem.h>


#include "rsa.h"
#include "str.h"




// 产生RSA密钥对


/*
输入参数：
	bits： 密钥强度，512/1024/2048等
	sizeofPK：公钥的缓存大小
	sizeofVK: 私钥的缓存大小
输出参数：
	pk:	公钥(可见字符串，扩张的DER格式BCD码)
	vk：    私钥(可见字符串，扩张的DER格式BCD码)
返回：
	>=0 成功
	<0 失败
*/

int GenRSADerKey(int bits,unsigned long  e,unsigned char *pk,int *pklen,unsigned char *vk,int *vklen)
{
	int ret = 0;
	RSA           *rsa=NULL;
	EVP_PKEY      *pkey=NULL;
	int len = 0;
	unsigned char *buf_out=NULL;
	char		buffer[8192]={0};


	pkey=EVP_PKEY_new();
	if ((rsa=RSA_generate_key(bits,e,NULL,NULL)) == NULL)
	{
		printf("in GenRSADerKey::RSA_generate_key[%d] failed!\n",bits);
		return -1;
	}
	//设置 EVP_PKEY 中的 RSA 密钥结构，使它代表该 RSA 密钥
	EVP_PKEY_assign_RSA(pkey,rsa);

	buf_out = pk;
	//取公钥
	if ((len = i2d_PublicKey(pkey,&buf_out))<=0)
	{
		EVP_PKEY_free(pkey);
		printf("in GenRSADerKey::i2d_PublicKey failed[%d] err!\n",len);
		return -1;
	}
	*pklen = len;

	//取私钥
	buf_out = vk;
	if ((len = i2d_PrivateKey(pkey,&buf_out))<=0)
	{
		EVP_PKEY_free(pkey);
		printf("in GenRSADerKey::i2d_PrivateKey failed[%d] err!\n",len);
		return -1;
	}
	*vklen = len;
	EVP_PKEY_free(pkey);  //由于EVP_PKEY_assign_RSA，调用这个已经释放了RSA, 故不能做RSA_free了.
	return 0;
}



// 用私钥加密
/*
输入参数：
	plaintxt： 二进制明文
	plaintxtLen：明文长度
	vk：       私钥(der编码的私钥)
	fillFlag:  填充方式，0无填充，1按pkcs1格式填充
输出参数：
	encTxt：加密的密文数据
返回：
	加密的密文数据长度
*/

int RSAVKEnc(unsigned char *vk,int vklen,unsigned char *plaintxt,int plaintxtLen,int fillFlag,unsigned char *encTxt)
{
	int ret = 0;
	int len = 0;
	EVP_PKEY        *pkey = NULL;
	RSA *rsakey = NULL;
	const unsigned char *const_buf = NULL;
	int keysize = 0;
	const_buf = vk;
	if ((pkey = d2i_PrivateKey(EVP_PKEY_RSA,NULL,&const_buf,vklen)) == NULL)
	{
		printf("in RSAVKEnc::d2i_PrivateKey failed at %s,line %d\n",__FILE__,__LINE__);
		return -1;
	}
	//获取 EVP_PKEY 的 RSA 密钥结构
	rsakey = EVP_PKEY_get1_RSA(pkey);
	if (!rsakey)
	{
		printf("in RSAVKEnc::EVP_PKEY_get1_RSA failed at %s,line %d\n",__FILE__,__LINE__);
		EVP_PKEY_free(pkey);
		return -2;
	}
	EVP_PKEY_free(pkey);
	//获取 RSA 密钥长度字节数
	keysize = RSA_size(rsakey);

	if(fillFlag == 0)//无填充
		len = RSA_private_encrypt(plaintxtLen,plaintxt,encTxt,rsakey,RSA_NO_PADDING);
	else
		len = RSA_private_encrypt(plaintxtLen,plaintxt,encTxt,rsakey,RSA_PKCS1_PADDING);
	RSA_free(rsakey);
	return len;
}


// 进行公钥解密
/*
输入参数：
	crypk： 二进制密文数据
	crypklen：密文数据长度
	pk：   公钥(der编码)
	pklen: 公钥长度
	fillFlag:  填充方式，0无填充，1按pkcs1格式填充
输出参数：
	plaintxt：明文数据
返回：
	解密后的明文数据长度
*/

int RSAPKDec(unsigned char *crypk,int crypklen,unsigned char *pk,int pklen,int fillFlag,unsigned char *plaintxt)
{
	int ret = 0;
	int len = 0;
	EVP_PKEY *pkey = NULL;
	RSA *rsakey = NULL;
	const unsigned char *const_buf = NULL;
	int keysize = 0;

	//der pk to pkey
	const_buf = pk;
	if ((pkey = d2i_PublicKey(EVP_PKEY_RSA,NULL,&const_buf,pklen)) == NULL)
	{
		printf("in RSAPKDec::d2i_PublicKey failed at %s,line %d\n",__FILE__,__LINE__);
		ret = -1;
	}
	rsakey = EVP_PKEY_get1_RSA(pkey);
	if (!rsakey)
	{
		printf("in RSAPKDec::EVP_PKEY_get1_RSA failed at %s,line %d\n",__FILE__,__LINE__);
		EVP_PKEY_free(pkey);
		return -2;
	}
	EVP_PKEY_free(pkey);

	//获取 RSA 密钥长度字节数
	keysize = RSA_size(rsakey);
	
	
	if(fillFlag == 0)//无填充
		len = RSA_public_decrypt(crypklen,crypk,plaintxt,rsakey,RSA_NO_PADDING);
	else//pkcs1
		len = RSA_public_decrypt(crypklen,crypk,plaintxt,rsakey,RSA_PKCS1_PADDING);
	RSA_free(rsakey);
	return len;
}




// 进行公钥加密
/*
输入参数：
	plaintxt： 明文二进制数据
	plaintxtlen：明文数据长度
	pk：       公钥(der)
	pklen:     公钥长度
	fillFlag:  填充方式，0无填充，1按pkcs1格式填充
输出参数：
	crypktxt：密文数据
返回：
	加密后的密文数据长度
*/
int RSAPKEnc(unsigned char *plaintxt,int plaintxtlen,unsigned char *pk,int pklen,int fillFlag,unsigned char *crypktxt)
{
	int ret = 0;
	int len = 0;
	EVP_PKEY *pkey = NULL;
	RSA* rsakey = NULL;
	int keysize = 0;
	const unsigned char *buf = NULL;
	buf = pk;
	if ((pkey = d2i_PublicKey(EVP_PKEY_RSA,NULL,&buf,pklen)) == NULL)
	{
		printf("in RSAPKEnc::d2i_PublicKey failed at %s,line %d\n",__FILE__,__LINE__);
		return -1;
	}
	rsakey = EVP_PKEY_get1_RSA(pkey);
	if (!rsakey)
	{
		printf("in RSAPKEnc::EVP_PKEY_get1_RSA failed at %s,line %d\n",__FILE__,__LINE__);
		EVP_PKEY_free(pkey);
		return -2;
	}
	EVP_PKEY_free(pkey);

	//获取 RSA 密钥长度字节数
	keysize = RSA_size(rsakey);
	

	if(fillFlag == 0)
		len = RSA_public_encrypt(plaintxtlen,plaintxt,crypktxt,rsakey,RSA_NO_PADDING);
	else
		len = RSA_public_encrypt(plaintxtlen,plaintxt,crypktxt,rsakey,RSA_PKCS1_PADDING);
	RSA_free(rsakey);
	return len;
}



// 用私钥解密
/*
输入参数：
	encTxt： 二进制密文
	encTxtLen：  密文长度
	vk：       私钥(der编码)
	vklen:     私钥长度
	fillFlag:  填充方式，0无填充，1按pkcs1格式填充
输出参数：
	plaintxt：解密后的明文数据
返回：
	解密的明文数据长度
*/
int RSAVKDec(unsigned char *encTxt,int encTxtLen,unsigned char *vk,int vklen,int fillFlag,unsigned char *plaintxt)
{
	int ret = 0;
	int len = 0;
	int keysize = 0;
	EVP_PKEY *pkey = NULL;
	RSA *rsakey = NULL;
	const unsigned char *buf = NULL;

	buf = vk;
	if ((pkey = d2i_PrivateKey(EVP_PKEY_RSA,NULL,&buf,vklen)) == NULL)
	{
		printf("in RSAVKDec::d2i_PrivateKey failed at %s,line %d\n",__FILE__,__LINE__);
		return -1;
	}
	rsakey = EVP_PKEY_get1_RSA(pkey);
	if (!rsakey)
	{
		printf("in RSAVKDec::EVP_PKEY_get1_RSA failed at %s,line %d\n",__FILE__,__LINE__);
		EVP_PKEY_free(pkey);
		return -2;
	}
	EVP_PKEY_free(pkey);
	keysize = RSA_size(rsakey);
	
	if(fillFlag == 0)
		len = RSA_private_decrypt(encTxtLen,encTxt,plaintxt,rsakey,RSA_NO_PADDING);
	else
		len = RSA_private_decrypt(encTxtLen,encTxt,plaintxt,rsakey,RSA_PKCS1_PADDING);

	RSA_free(rsakey);
	return len;
}






