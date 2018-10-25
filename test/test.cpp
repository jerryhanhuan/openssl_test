
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/stat.h>
#include <stdarg.h>



#include "hashInterface.h"
#include "str.h"
#include "smAPI.h"


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
	printf("06		OID transfer");
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


