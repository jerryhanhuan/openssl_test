
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/stat.h>
#include <stdarg.h>



#include "hashInterface.h"
#include "str.h"
#include "smAPI.h"
#include "macro.h"
#include "Asn1Interface.h"
#include "rsaInterface.h"


char	pgUnionInputStr[8192+1];
int IsQuit(char *p)
{
	ToUpperCase(p);
	if ((strcmp(p,"QUIT") == 0) || (strcmp(p,"EXIT") == 0))
		return(1);
	else
		return(0);
}



char *Input(const char *fmt,...)
{
	va_list args;
	int	i;

	va_start(args,fmt);
	vprintf(fmt,args);
	va_end(args);

	for (i = 0; i < sizeof(pgUnionInputStr)-1;)
	{
		pgUnionInputStr[i] = getchar();
		if ((pgUnionInputStr[i] == 10) || (pgUnionInputStr[i] == 13) || (pgUnionInputStr[i] == '\n'))
		{
			if (i == 0)
				continue;
			else
				break;
		}
		else
			i++;
	}
	pgUnionInputStr[i] = 0;
	return(pgUnionInputStr);
}


int test_hash()
{
	int ret = 0;
	char *ptr = NULL;
	ptr = Input("please select hash:: 0-SHA1 1-SHA224 2-SHA256 3-SHA384 4-SHA512 5-MD5 ::");
	int hashID = atoi(ptr);
	char dataHex[8192]={0};
	unsigned char data[8192]={0};
	int datalen = 0;
	unsigned char hashval[128]={0};
	int len = 0;
	char hashValHex[256]={0};

	ptr = Input("please input data(H)::");
	datalen = aschex_to_bcdhex(ptr,strlen(ptr),(char*)data);
	if ((len = DigestWithOpenssl(hashID,data,datalen,hashval))<0)
	{
		printf("DigestWithOpenssl failed ret[%d]\n",ret);
		return -1;
	}
	bcdhex_to_aschex((char*)hashval,len,hashValHex);
	printf("hashval is %s\n",hashValHex);
	return 0;
}


int test_PBKDF2WithOpenssl()
{

	int ret = 0;
	char *ptr = NULL;
	ptr = Input("please select hash:: 0-SHA1 1-SHA224 2-SHA256 3-SHA384 4-SHA512 5-MD5 ::");
	int hashID = atoi(ptr);
	unsigned char pass[1024]={0};
	int iter = 0;
	unsigned char salt[1024]={0};
	int saltlen = 0;
	int keylen = 0;
	unsigned char key[1024]={0};
	char keyHex[2018+1]={0};
	
	ptr = Input("please input pass::");
	strcpy((char*)pass,ptr);
	ptr = Input("please input Salt(H)::");
	saltlen = aschex_to_bcdhex(ptr,strlen(ptr),(char*)salt);
	ptr = Input("please input iter::");
	iter = atoi(ptr);
	ptr = Input("please input keylen::");
	keylen = atoi(ptr);
	
	if ((ret = PBKDF2WithOpenssl(hashID,pass,strlen((char*)pass),salt,saltlen,iter,keylen,key))<0)
	{
		printf("PBKDF2WithOpenssl failed \n");
		return -1;
	}
	bcdhex_to_aschex((char*)key,keylen,keyHex);
	printf("key::%s\n",keyHex);
	return 0;
}

int test_SM3()
{
	unsigned char data[8192]={0};
	char *ptr = NULL;
	ptr = Input("Please input data(H)::");
	int len = aschex_to_bcdhex(ptr,strlen(ptr),(char*)data);
	unsigned char hash[33]={0};
	char hashValHex[65]={0};
	SoftSM3(data,len,hash);
	bcdhex_to_aschex((char*)hash,32,hashValHex);
	printf("hash::%s\n",hashValHex);
	return 0;
}

int test_HMAC_SM3()
{
	int ret = 0;
	unsigned char key[256]={0};
	char *ptr = NULL;
	int keylen = 0;
	unsigned char data[1024]={0};
	int datalen = 0;
	unsigned char mac[32]={0};
	char macHex[65]={0};

	ptr = Input("please input key(H)::");
	keylen = aschex_to_bcdhex(ptr,strlen(ptr),(char*)key);
	ptr = Input("please input data(H)::");
	datalen = aschex_to_bcdhex(ptr,strlen(ptr),(char*)data);

	if ((ret = SoftHMAC_SM3(key,keylen,data,datalen,mac))<0)
	{
		printf("SoftHMAC_SM3 failed \n");
	}else{
		bcdhex_to_aschex((char*)mac,ret,macHex);
		printf("mac::%s\n",macHex);
	}
	memset(mac,0,sizeof(mac));
	memset(macHex,0,sizeof(macHex));
	
	if ((ret = SoftHMAC_SM32(key,keylen,data,datalen,mac))<0)
	{
		printf("SoftHMAC_SM3 failed \n");
	}else{
		bcdhex_to_aschex((char*)mac,ret,macHex);
		printf("mac::%s\n",macHex);
	}
	return 0;
}

int test_HMAC()
{

	int ret = 0;
	char *ptr = NULL;
	ptr = Input("please select hash:: 0-SHA1 1-SHA224 2-SHA256 3-SHA384 4-SHA512 5-MD5 ::");
	int hashID = atoi(ptr);
	char dataHex[8192]={0};
	unsigned char data[8192]={0};
	int datalen = 0;
	unsigned char hashval[128]={0};
	int len = 0;
	char hashValHex[256]={0};
	unsigned char key[1024]={0};
	int keylen = 0;
	ptr = Input("please input key(H)::");
	keylen = aschex_to_bcdhex(ptr,strlen(ptr),(char*)key);


	ptr = Input("please input data(H)::");
	datalen = aschex_to_bcdhex(ptr,strlen(ptr),(char*)data);
	if ((len = HMACWithOpenssl(hashID,key,keylen,data,datalen,hashval))<0)
	{
		printf("DigestWithOpenssl failed ret[%d]\n",ret);
		return -1;
	}
	bcdhex_to_aschex((char*)hashval,len,hashValHex);
	printf("HMAC is %s\n",hashValHex);
	return 0;
}


int test_SHA3()
{


	int ret = 0;
	int hashID = 0;
	char *ptr = NULL;
	ptr = Input("please select hash:: 0:SHA3-224 1:SHA3-256 2:SHA3-384 3:SHA3-512 ::");
	ret = atoi(ptr);
	switch(ret)
	{
		case 0:
			hashID = H_SHA3_224;
			break;
		case 1:
			hashID = H_SHA3_256;
			break;
		case 2:
			hashID = H_SHA3_384;
			break;
		case 3:
			hashID = H_SHA3_512;
			break;
		default:
			printf("wrong choice\n");
			return -1;
	}

	char dataHex[8192]={0};
	unsigned char data[8192]={0};
	int datalen = 0;
	unsigned char hashval[128]={0};
	int len = 0;
	char hashValHex[256]={0};

	ptr = Input("please input data(H)::");
	datalen = aschex_to_bcdhex(ptr,strlen(ptr),(char*)data);

	ret = SHA3(hashID,data,datalen,hashval);
	bcdhex_to_aschex((char*)hashval,ret,hashValHex);
	printf("hash::[%s]\n",hashValHex);
	return 0;
}


int test_KECCAK()
{


	int ret = 0;
	int hashID = 0;
	char *ptr = NULL;
	ptr = Input("please select hash:: 0:KECCAK-224 1:KECCAK-256 2:KECCAK-384 3:KECCAK-512 ::");
	ret = atoi(ptr);
	switch(ret)
	{
		case 0:
			hashID = H_KECCAK_224;
			break;
		case 1:
			hashID = H_KECCAK_256;
			break;
		case 2:
			hashID = H_KECCAK_384;
			break;
		case 3:
			hashID = H_KECCAK_512;
			break;
		default:
			printf("wrong choice\n");
			return -1;
	}

	char dataHex[8192]={0};
	unsigned char data[8192]={0};
	int datalen = 0;
	unsigned char hashval[128]={0};
	int len = 0;
	char hashValHex[256]={0};

	ptr = Input("please input data(H)::");
	datalen = aschex_to_bcdhex(ptr,strlen(ptr),(char*)data);

	ret = keccak(hashID,data,datalen,hashval);
	bcdhex_to_aschex((char*)hashval,ret,hashValHex);
	printf("hash::[%s]\n",hashValHex);
	return 0;
}

int test_sm4()
{

	int ret = 0;
	char *ptr = NULL;
	ptr = Input("Please select SM4 mode:: 1-ENC_ECB 2-DEC_ECB 3- ENC_CBC 4-DEC_CBC::");
	int mode = atoi(ptr);
	unsigned char key[16]={0};
	char keyHex[33]={0};
	unsigned char data[8192]={0};
	char dataHex[8192]={0};
	unsigned char out[8192]={0};
	char outHex[8192]={0};
	int datalen = 0;

	ptr = Input("Please input key(H)::");
	strcpy(keyHex,ptr);
	aschex_to_bcdhex(keyHex,strlen(keyHex),(char*)key);

	ptr = Input("Please input data(H)::");
	strcpy(dataHex,ptr);
	datalen = aschex_to_bcdhex(dataHex,strlen(dataHex),(char*)data);

	int algmode = 0;
	char IVHex[33]={0};
	unsigned char IV[16]={0};
	int len = 0;

	switch(mode)
	{
		case 1:
			algmode = ENC_ECB;
			ret = SoftSM4EncryptWithECB(key,data,datalen,out);
			break;
		case 2:
			algmode = DEC_ECB;
			ret = SoftSM4DecryptWithECB(key,data,datalen,out);
			break;
		case 3:
			algmode = ENC_CBC;
			ptr = Input("Please input IV(H)::");
			strcpy(IVHex,ptr);
			aschex_to_bcdhex(IVHex,strlen(IVHex),(char*)IV);
			ret = SoftSM4EncryptWithCBC(key,IV,data,datalen,out);
			break;
		case 4:
			algmode = DEC_CBC;
			ptr = Input("Please input IV(H)::");
			strcpy(IVHex,ptr);
			aschex_to_bcdhex(IVHex,strlen(IVHex),(char*)IV);
			ret = SoftSM4DecryptWithCBC(key,IV,data,datalen,out);
			break;
		default:
			printf("not support this mode\n");
			return -1;
	}
	
	bcdhex_to_aschex((char*)out,ret,outHex);
	printf("out::%s\n",outHex);
	return 0;
}


int testOID()
{
	int ret = 0;
	char *ptr = NULL;
	char oidHex[256]={0};
	unsigned char oid[256]={0};
	int oidlen = 0;
	char oid_numerical[256]={0};
	ptr = Input("please select :: 1-Oid2Hex 2-Hex2Oid::");
	int choice = atoi(ptr);
	switch(choice)
	{
		case 1:
			ptr = Input("please input numerical OID::");
			strcpy(oid_numerical,ptr);
			ret = NumOid2Hex(oid_numerical,oid,&oidlen);
			bcdhex_to_aschex((char*)oid,oidlen,oidHex);
			printf("oidHex::%s\n",oidHex);
			break;
		case 2:
			ptr = Input("please input OIDHex::");
			strcpy(oidHex,ptr);
			oidlen = aschex_to_bcdhex(oidHex,strlen(oidHex),(char*)oid);
			ret = OidHex2Num(oid,oidlen,oid_numerical);
			printf("oid numerical::%s\n",oid_numerical);
			break;
		default:
			printf("not support choice[%d]\n",choice);
			break;
	}
	return 0;
}


int testASN1()
{
	int ret = 0;
	char choice[128]={0};
	loop:
#ifdef WIN32
	ret = system("cls");
#else
	ret = system("clear");
#endif
	printf("ASN1 test::\n");
	printf("01		Oid\n");
	printf("Exit	exit\n");
	printf("\n");

	printf("please select choice::");
	
#ifdef  WIN32
	ret = scanf("%s",choice);
#else
	ret = scanf("%s",choice);
#endif
	
	if ((strcmp(choice,"EXIT") == 0) || (strcmp("QUIT",choice) == 0))
		return(0);
	int c = atoi(choice);
	switch (c)
	{
	case 1:
		testOID();
		break;
	default:
		printf("not support the choice\n");
		break;
	}

	printf("please enter... ...");
	getchar();
	getchar();
	goto loop;

	return 0;


}


int test_RSA_pwd()
{

	int ret = 0;
	char password[128]={0};
	unsigned char dervk[2048]={0};
	char dervkHex[4096]={0};
	char vkbypwdPEM[8192]={0};
	char *ptr = NULL;
	ptr = Input("请输入VK(H)::");
	strcpy(dervkHex,ptr);
	int vklen = aschex_to_bcdhex(dervkHex,strlen(dervkHex),(char*)dervk);
	ptr = Input("请输入password::");
	strcpy(password,ptr);

	if((ret = EncryptDerVkBypassword(dervk,vklen,password,vkbypwdPEM))<0)
	{
		printf("EncryptDerVkBypassword failed \n");
		return ret;
	}
	printf("私钥密文::\n");
	printf("%s\n",vkbypwdPEM);
	memset(dervk,0,sizeof(dervk));
	if((vklen = DecryptPEMVk2Der(vkbypwdPEM,ret,password,dervk))<0)
	{
		printf("DecryptPEMVk2Der failed \n ");
		return vklen;
	}
	memset(dervkHex,0,sizeof(dervkHex));
	bcdhex_to_aschex((char*)dervk,vklen,dervkHex);
	printf("vk::\n");
	printf("%s\n",dervkHex);
	return 0;
}





int main()
{
	int ret = 0;
	char choice[128]={0};
	loop:
#ifdef WIN32
	ret = system("cls");
#else
	ret = system("clear");
#endif

	
	
	printf("alg test::\n");
	printf("01		hash\n");
	printf("02		PBKDF2\n");
	printf("03		SM3\n");
	printf("04		HMAC_SM3\n");
	printf("05		HMAC\n");
	printf("06		SHA3\n");
	printf("07		Keccak\n");
	printf("08		SM4\n");
	printf("09		ASN1\n");
	printf("10		RSA2pemByPasswd\n");
	printf("Exit	exit\n");
	printf("\n");

	printf("please select choice::");
	
#ifdef  WIN32
	ret = scanf("%s",choice);
#else
	ret = scanf("%s",choice);
#endif
	
	if ((strcmp(choice,"EXIT") == 0) || (strcmp("QUIT",choice) == 0))
		return(0);
	int c = atoi(choice);
	switch (c)
	{
	case 1:
		test_hash();
		break;
	case 2:
		test_PBKDF2WithOpenssl();
		break;
	case 3:
		test_SM3();
		break;
	case 4:
		test_HMAC_SM3();
		break;
	case 5:
		test_HMAC();
		break;
	case 6:
		test_SHA3();
		break;
	case 7:
		test_KECCAK();
		break;
	case 8:
		test_sm4();
		break;
	case 9:
		testASN1();
		break;
	case 10:
		test_RSA_pwd();
		break;
	default:
		printf("not support the choice\n");
		break;
	}

	printf("please enter... ...");
	getchar();
	getchar();
	goto loop;

	return 0;
}


