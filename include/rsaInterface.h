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






#ifdef __cplusplus
}
#endif


#endif