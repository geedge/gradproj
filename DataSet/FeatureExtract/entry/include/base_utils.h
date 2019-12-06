#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <net/if.h>
#include <string.h>
#include <pthread.h>
#include "MESA/MESA_handle_logger.h"

#ifndef MAX
#define MAX(a, b)  	(((a) > (b)) ? (a) : (b))
#endif

#ifndef MIN
#define MIN(a, b)  	(((a) < (b)) ? (a) : (b))
#endif

#define STRING_MAX 128 

#define likely(expr)    __builtin_expect((expr), 1)
#define unlikely(expr)  __builtin_expect((expr), 0)

#define ALLOC(type, number) ((type *)calloc(sizeof(type), number))
#define	FREE(p)	{free(*p);*p=NULL;}

#define LOG_ERROR(handler, fmt, ...)															\
do { 													\
	MESA_handle_runtime_log(handler, RLOG_LV_FATAL, "kni", fmt, ##__VA_ARGS__); } while(0)			

#define LOG_INFO(handler, fmt, ...)															\
do { 													\
	MESA_handle_runtime_log(handler, RLOG_LV_INFO, "kni", fmt, ##__VA_ARGS__); } while(0)			

#define LOG_DEBUG(handler, fmt, ...)															\
do { 													\
	MESA_handle_runtime_log(handler, RLOG_LV_DEBUG, "kni", fmt, ##__VA_ARGS__); } while(0)	

	