#ifndef _T_RSA_INTERFACE_H
#define _T_RSA_INTERFACE_H


#ifdef __cplusplus
extern "C"{
#endif


//生成RSA密钥
int RSAGenDerKey(int bits,unsigned long  e,unsigned char *pk,int *pklen,unsigned char *vk,int *vklen);


//私钥 PKCS1 加密
int VKEncPKCS1(unsigned char *vk,int vklen,unsigned char *plainTxt,int plainTxtLen,unsigned char *encTxt);


//私钥加密(不填充)
int VKEnc(unsigned char *vk,int vklen,unsigned char *plainTxt,int plainTxtLen,unsigned char *encTxt);

//公钥PKCS1解密
int PKDecPKCS1(unsigned char *pk,int pklen,unsigned char *cryptTxt,int cryptTxtLen,unsigned char *plainTxt);

//公钥解密(不填充)
int PKDec(unsigned char *pk,int pklen,unsigned char *cryptTxt,int cryptTxtLen,unsigned char *plainTxt);

//公钥加密 PKCS1
int PKEncPKCS1(unsigned char *pk,int pklen,unsigned char *plainTxt,int plainTxtLen,unsigned char *cryptTxt);

//公钥加密(不填充)
int PKEnc(unsigned char *pk,int pklen,unsigned char *plainTxt,int plainTxtLen,unsigned char *cryptTxt);

//私钥解密 PKCS1
int VKDecPKCS1(unsigned char *vk,int vklen,unsigned char *cryptTxt,int cryptTxtLen,unsigned char *plainTxt);

//私钥解密(不填充)
int VKDec(unsigned char *vk,int vklen,unsigned char *cryptTxt,int cryptTxtLen,unsigned char *plainTxt);

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

int EncryptDerVkBypassword(unsigned char *dervk,int vklen,char *passwd,char *vkbypasswd);



/*
功能: 用口令加密RSA私钥明文得到私钥密文(PKCS#1)
输入:
	dervk: der 格式的私钥明文
	vklen:私钥明文长度
	passwd: 私钥保护口令
输出:
	vkbypasswd: 私钥密文
返回:
	>0 私钥密文的长度
	<0 失败
reference https://www.openssl.org/docs/man1.1.0/crypto/PEM_write_bio_PrivateKey.html
	
	
*/

int EncryptDerVkBypasswordEx(unsigned char *dervk,int vklen,char *passwd,char *vkbypasswd);



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

int DecryptPEMVk2Der(char *vkbypasswd,int vklen,char *passwd,unsigned char *derVK);







#ifdef __cplusplus
}
#endif


#endif