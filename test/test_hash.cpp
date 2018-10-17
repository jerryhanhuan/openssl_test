
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/stat.h>
#include <stdarg.h>

#include "hashInterface.h"
#include "str.h"


static char	pgUnionInputStr[8192+1];
static int IsQuit(char *p)
{
	ToUpperCase(p);
	if ((strcmp(p,"QUIT") == 0) || (strcmp(p,"EXIT") == 0))
		return(1);
	else
		return(0);
}



static char *Input(char *fmt,...)
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
	ptr = Input("请选择Hash 算法:: 0-SHA1 1-SHA224 2-SHA256 3-SHA384 4-SHA512 5-MD5 ::");
	int hashID = atoi(ptr);
	char dataHex[8192]={0};
	unsigned char data[8192]={0};
	int datalen = 0;
	unsigned char hashval[128]={0};
	int len = 0;
	char hashValHex[256]={0};

	ptr = Input("请输入数据(H)::");
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
	ptr = Input("请选择Hash 算法:: 0-SHA1 1-SHA224 2-SHA256 3-SHA384 4-SHA512 5-MD5 ::");
	int hashID = atoi(ptr);
	unsigned char pass[1024]={0};
	int iter = 0;
	unsigned char salt[1024]={0};
	int saltlen = 0;
	int keylen = 0;
	unsigned char key[1024]={0};
	char keyHex[2018+1]={0};
	
	ptr = Input("请输入pass::");
	strcpy((char*)pass,ptr);
	ptr = Input("请输入Salt(H)::");
	saltlen = aschex_to_bcdhex(ptr,strlen(ptr),(char*)salt);
	ptr = Input("请输入迭代次数::");
	iter = atoi(ptr);
	ptr = Input("请输入需要生成的密钥长度::");
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




int main()
{
	char choice[128]={0};
	loop:
#ifdef WIN32
	system("cls");
#else
	system("clear");
#endif

	
	
	printf("HASH 测试::\n");
	printf("01		hash\n");
	printf("02		PBKDF2\n");
	printf("Exit	退出\n");
	printf("\n");

	printf("请选择::");
	
#ifdef  WIN32
	scanf_s("%s",choice);
#else
	scanf("%s",choice);
#endif
	
	if ((strcmp(choice,"EXIT") == 0) || (strcmp("QUIT",choice) == 0))
		return(0);
	switch (atoi(choice))
	{
	case 1:
		test_hash();
		break;
	case 2:
		test_PBKDF2WithOpenssl();
		break;


	}

	printf("请按回车键继续... ...");
	getchar();
	getchar();
	goto loop;

	return 0;
}


