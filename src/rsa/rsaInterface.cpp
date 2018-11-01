#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
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
    return GenRSADerKey(bits,e,pk,pklen,)vk,vklen;
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

