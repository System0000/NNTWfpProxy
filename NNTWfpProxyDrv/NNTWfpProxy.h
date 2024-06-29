#pragma once
#ifndef NNTWfpProxy_H
#define NNTWfpProxy_H
#include <initguid.h>
#include <ntddk.h>
#define NDIS620
#include <ndis.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <ip2string.h>
#include <mstcpip.h>
#include "NNTWfpProxyStruct.h"
#define RedirectIP IP_TO_HEX(127,0,0,1)
#define RedirectPORT 9870
DEFINE_GUID(NNT_WFP_NET_OUTBOUND_CALLOUT_GUID, 0x60, 0x70, 0x80, 0x90, 0xce, 0xec, 0x7c, 0xc7, 0x32, 0x23, 0x49);
DEFINE_GUID(NNT_WFP_NET_INBOUND_CALLOUT_GUID, 0x06, 0x07, 0x08, 0x09, 0xec, 0xce, 0xc7, 0x7c, 0x23, 0x32, 0x94);
DEFINE_GUID(NNT_WFP_NET_SUBLAYER_GUID, 0x11, 0x45, 0x14, 0x19, 0x19, 0x81, 0x00, 0x00, 0x00, 0x00, 0x00);
DEFINE_GUID(NNT_WFP_NET_OUTBOUND_FILTER_GUID, 0x11, 0x54, 0x14, 0x19, 0x19, 0x81, 0x00, 0x00, 0x00, 0x00, 0x00);
DEFINE_GUID(NNT_WFP_NET_INBOUND_FILTER_GUID, 0x10, 0x45, 0x41, 0x19, 0x19, 0x81, 0x00, 0x00, 0x00, 0x00, 0x00);
DEFINE_GUID(NNT_WFP_NET_PROVIDER_GUID, 0x10, 0x45, 0x41, 0x19, 0x19, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00);
typedef struct _IPV4_HEADER
{
    UINT8  VersionAndHeaderLength;
    UINT8  TypeOfService;
    UINT16 TotalLength;
    UINT16 Identification;
    UINT16 FlagsAndFragmentOffset;
    UINT8  TimeToLive;
    UINT8  Protocol;
    UINT16 Checksum;
    UINT32 SourceAddress;
    UINT32 DestinationAddress;
} IPV4_HEADER,*PIPV4_HEADER;

extern PDEVICE_OBJECT DeviceObject;
extern HANDLE EngineHandle;
extern UINT32 RegCalloutId, AddCalloutId;
extern UINT64 FilterId;
extern LIST_ENTRY ConnectIPListHead;

NTSTATUS InitializeWfp();
VOID UnInitWfp();
void UpdateIpv4HeaderChecksum(PIPV4_HEADER IpHeader, UINT32 IpHeaderSize);
VOID OutBoundConnectFilterCallBack(const FWPS_INCOMING_VALUES0* inFixedValues,const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,void* layerData,const void* classifyContext,const FWPS_FILTER1* filter,UINT64 flowContext, FWPS_CLASSIFY_OUT0* classifyOut);
VOID InBoundConnectFilterCallBack(const FWPS_INCOMING_VALUES0* inFixedValues, const FWPS_INCOMING_METADATA_VALUES0* inMetaValues, void* layerData, const void* classifyContext, const FWPS_FILTER1* filter, UINT64 flowContext, FWPS_CLASSIFY_OUT0* classifyOut);
VOID Unload(PDRIVER_OBJECT DriverObject);
void NTAPI DriverDatagramDataInjectComplete(_In_ void* context,_Inout_ NET_BUFFER_LIST* netBufferList,_In_ BOOLEAN dispatchLevel);//Deprecated
NTSTATUS NotifyCallBack(FWPS_CALLOUT_NOTIFY_TYPE type, GUID* filterkey, FWPS_FILTER* filter);
VOID FlowDeleteCallBack(UINT16 layerid, UINT32 calloutid, UINT64 flowcontext);
NTSTATUS WfpOpenEngine();
NTSTATUS WfpCreateProvider();
NTSTATUS WfpRegisterCallout();
NTSTATUS WfpAddCallout();
NTSTATUS WfpAddSublayer();
NTSTATUS WfpAddFilter();
#endif 

