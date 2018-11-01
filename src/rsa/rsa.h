#ifndef _T_RSA_H__
#define _T_RSA_H__

#ifdef __cplusplus
extern "C"{
#endif



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

int GenRSADerKey(int bits,unsigned long  e,unsigned char *pk,int *pklen,unsigned char *vk,int *vklen);


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

int RSAVKEnc(unsigned char *vk,int vklen,unsigned char *plaintxt,int plaintxtLen,int fillFlag,unsigned char *encTxt);


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

int RSAPKDec(unsigned char *crypk,int crypklen,unsigned char *pk,int pklen,int fillFlag,unsigned char *plaintxt);


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
int RSAPKEnc(unsigned char *plaintxt,int plaintxtlen,unsigned char *pk,int pklen,int fillFlag,unsigned char *crypktxt);


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
int RSAVKDec(unsigned char *encTxt,int encTxtLen,unsigned char *vk,int vklen,int fillFlag,unsigned char *plaintxt);











#ifdef __cplusplus
}
#endif
#endif