#ifndef __OPENSSL_INIT_H
#define __OPENSSL_INIT_H

#ifdef __cplusplus
extern "C"{
#endif

/*
	功能:加载OpenSSL的算法,程序初始化时调用
	//多线程下,注意加锁
*/
	
void init_OpenSSL();


#ifdef __cplusplus
}
#endif

#endif