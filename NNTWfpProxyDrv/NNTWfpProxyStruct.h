#pragma once
#ifndef NNTWfpProxyStruct_H
#define NNTWfpProxyStruct_H
#include "wdm.h"
#define MAKE_IPADDRESS_V4(a, b, c, d) ((ULONG)(((ULONG)(a) << 24) | ((ULONG)(b) << 16) | ((ULONG)(c) << 8) | (ULONG)(d)))
#define IPADDRESS_TO_KERNEL(x) ((((x) & 0xFF) << 24) | (((x) & 0xFF00) << 8) | (((x) & 0xFF0000) >> 8) | (((x) & 0xFF000000) >> 24))
#define NNTWfpProxy_UDP 0
#define NNTWfpProxy_TCP 1
typedef struct
{
	DWORD32 SourceIPV4;
	USHORT SourcePort;
	USHORT ConnectProtocol;
	DWORD32 Reserve[4];
}NNTWfpContext,*pNNTWfpContext;
#endif