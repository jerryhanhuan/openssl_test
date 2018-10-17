#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#ifdef WIN32
	#include <Windows.h>
	#include <io.h>
#else
	#include <unistd.h>
	#include <pthread.h>
#endif


#include "openssl_init.h"



#if defined(WIN32)
    #define MUTEX_TYPE HANDLE
    #define MUTEX_SETUP(x) (x) = CreateMutex(NULL, FALSE, NULL)
    #define MUTEX_CLEANUP(x) CloseHandle(x)
    #define MUTEX_LOCK(x) WaitForSingleObject((x), INFINITE)
    #define MUTEX_UNLOCK(x) ReleaseMutex(x)
    #define THREAD_ID GetCurrentThreadId( )
#elif defined (_POSIX_THREADS)
    /* _POSIX_THREADS is normally defined in unistd.h if pthreads are available
       on your platform. */
    #define MUTEX_TYPE pthread_mutex_t
    #define MUTEX_SETUP(x) pthread_mutex_init(&(x), NULL)
    #define MUTEX_CLEANUP(x) pthread_mutex_destroy(&(x))
    #define MUTEX_LOCK(x) pthread_mutex_lock(&(x))
    #define MUTEX_UNLOCK(x) pthread_mutex_unlock(&(x))
    #define THREAD_ID pthread_self( )
#else
    #error You must define mutex operations appropriate for your platform!
#endif

/* This array will store all of the mutexes available to OpenSSL. */ 
static MUTEX_TYPE *mutex_buf = NULL ;

int gLoadOpenSSLAlgFlag=0; // 算法加载标识，同一进程只用加载一次

static void locking_function(int mode, int n, const char * file, int line)
{
	if (mode & CRYPTO_LOCK)
		MUTEX_LOCK(mutex_buf[n]);
	else
		MUTEX_UNLOCK(mutex_buf[n]);
}

static unsigned long id_function(void)
{
	return ((unsigned long)THREAD_ID);
}

int thread_setup(void)
{
	int i;

	mutex_buf = (MUTEX_TYPE *)malloc(CRYPTO_num_locks() * sizeof(MUTEX_TYPE));
	if (!mutex_buf)
		return 0;
	for (i = 0;  i < CRYPTO_num_locks(  );  i++)
		MUTEX_SETUP(mutex_buf[i]);
	CRYPTO_set_id_callback(id_function);
	CRYPTO_set_locking_callback(locking_function);
	return 1;
}

int thread_cleanup(void)
{
	int i;
	if (!mutex_buf)
		return 0;
	CRYPTO_set_id_callback(NULL);
	CRYPTO_set_locking_callback(NULL);
	for (i = 0;  i < CRYPTO_num_locks(  );  i++)
		MUTEX_CLEANUP(mutex_buf[i]);
	free(mutex_buf);
	mutex_buf = NULL;
	return 1;
}

/*
	功能:加载OpenSSL的算法,程序初始化时调用
	//多线程下,注意加锁
*/
	

void init_OpenSSL()
{
	if (gLoadOpenSSLAlgFlag)
		return;
	thread_setup();
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	gLoadOpenSSLAlgFlag = 1;
}





