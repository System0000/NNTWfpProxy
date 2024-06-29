extern "C"
{
#include "NNTWfpProxy.h"
#include "ws2def.h"
}
#define DNS_PORT 53
#define RedirectPort 9870
HANDLE EngineHandle = NULL;
HANDLE InjectHandle = NULL;
HANDLE RedirectHandle=NULL;
UINT32 RegCalloutId = 0, AddCalloutId = 0;
UINT64 FilterId = 0;
NTSTATUS NotifyCallBack(FWPS_CALLOUT_NOTIFY_TYPE type, GUID* filterkey, FWPS_FILTER* filter)
{
	return STATUS_SUCCESS;
}
VOID FlowDeleteCallBack(UINT16 layerid, UINT32 calloutid, UINT64 flowcontext)
{
	return;
}
void UpdateIpv4HeaderChecksum(PIPV4_HEADER IpHeader, UINT32 IpHeaderSize)
{
	UINT32 Checksum = 0;
	UINT32 WordCount = IpHeaderSize / sizeof(UINT16);
	UINT16* Header = (UINT16*)IpHeader;

	IpHeader->Checksum = 0;

	for (UINT8 WordIndex = 0; WordIndex < WordCount; WordIndex++)
	{
		Checksum += Header[WordIndex];
	}

	Checksum = (Checksum & 0x0000ffff) + (Checksum >> 16);
	Checksum += (Checksum >> 16);

	IpHeader->Checksum = (UINT16)~Checksum;
}
VOID OutBoundConnectFilterCallBack(
	           const FWPS_INCOMING_VALUES0* inFixedValues,
	           const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
		       void* layerData,
			   const void* classifyContext,
	           const FWPS_FILTER1* filter,
	           UINT64 flowContext,
		       FWPS_CLASSIFY_OUT0* classifyOut
)
{
	NTSTATUS Status{0};
	FWPS_CONNECT_REQUEST* ConnectRequest{0};
	UINT64 classifyHandle{ 0 };

	UINT32 LocalAddress = inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_LOCAL_ADDRESS].value.uint32;
	UINT32 LocalPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_LOCAL_PORT].value.uint16;
	UINT32 RemoteAddress = inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_ADDRESS].value.uint32;
	UINT16 RemotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_PORT].value.uint16;
	UINT16 ConnectProtocol = inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_PROTOCOL].value.uint8;
	classifyOut->actionType = FWP_ACTION_PERMIT;
	classifyOut->rights |= FWPS_RIGHT_ACTION_WRITE;

	if (RemotePort == DNS_PORT)
	{
		return;
	}

	Status = FwpsAcquireClassifyHandle((void*)classifyContext, 0, &classifyHandle);
	if (!NT_SUCCESS(Status))
	{
		return;
	}
	//When making a TCP connection in the third ring, it will be infinitely redirected by the current callback function. 
	You need to record the redirection record through WSAIoctl in the third ring. Through this, you can judge whether it has been recorded (redirected). If so, no redirection will be performed. Orientation
	/*You can use WSAIoctl like this, redirectRecords is a buffer pointer. I don’t know what it is. It seems that it can’t be used without filling in this parameter, so I allocated a 4096-byte buffer for it.
	WSAIoctl(ClientSocket, SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS, 0, 0,redirectRecords, sizeof(redirectRecords), &bytesReturned, 0, 0);
	WSAIoctl(ServerSocket, SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS, redirectRecords, sizeof(redirectRecords), 0, 0, &bytesReturned, 0, 0);*/

	FWPS_CONNECTION_REDIRECT_STATE RedirectState = FwpsQueryConnectionRedirectState(inMetaValues->redirectRecords,RedirectHandle,NULL);
	
	
	if (RedirectState!=FWPS_CONNECTION_NOT_REDIRECTED) 
	{
		goto Exit;
	}
	
	Status = FwpsAcquireWritableLayerDataPointer0(classifyHandle, filter->filterId, 0, (PVOID*)&ConnectRequest, classifyOut);
	if (!NT_SUCCESS(Status)) 
	{
		goto Exit;
	}

	pNNTWfpContext pNNTWfpContextBuffer = (pNNTWfpContext)ExAllocatePool(NonPagedPool, sizeof(NNTWfpContext));  /*It seems that the applied buffer does not need to be released, because it seems that wfp will release it internally.*/
	if (!pNNTWfpContextBuffer) 
	{
		goto Exit;
	}
	pNNTWfpContextBuffer->SourceIPV4 = RemoteAddress;
	pNNTWfpContextBuffer->SourcePort = RemotePort;
	pNNTWfpContextBuffer->ConnectProtocol = ConnectProtocol==0x06?NNTWfpProxy_TCP:NNTWfpProxy_UDP;

	ConnectRequest->localRedirectContext = pNNTWfpContextBuffer;
	ConnectRequest->localRedirectContextSize = sizeof(NNTWfpContext);
																	
									/*Put the original IP port information in a buffer and convert it into a redirection context (something only available on win7 and above), and then use it on the client
									WSAIoctl(ClientSocket, SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT, 0, 0
									,redirectContext, sizeof(NNTWfpContext), &bytesReturned, 0, 0)
									Get the redirection context, which is the buffer that stores the original IP information, 
									read the original IP and forward it to the target proxy server*/
	IN_ADDR RedirectAddress{ 0 };
	RedirectAddress.S_un.S_addr = IPADDRESS_TO_KERNEL(MAKE_IPADDRESS_V4(127, 0, 0, 1));

	ConnectRequest->localRedirectHandle = RedirectHandle;
	ConnectRequest->localRedirectTargetPID = 0xFFFF;
								/*It seems that this does not need to be written according to the standard, 
								because I can still get the redirection context in the third ring by filling it with 0xFFFF.*/

	INETADDR_SET_ADDRESS((SOCKADDR*)&ConnectRequest->remoteAddressAndPort, (UCHAR*)&RedirectAddress);
	INETADDR_SET_PORT((SOCKADDR*)&ConnectRequest->remoteAddressAndPort, RtlUshortByteSwap(RedirectPort));

	FwpsApplyModifiedLayerData(classifyHandle, ConnectRequest, 0);
	FwpsReleaseClassifyHandle(classifyHandle);
	classifyHandle = 0;

Exit:
	FwpsReleaseClassifyHandle(classifyHandle);
	return;
}
VOID InBoundConnectFilterCallBack(const FWPS_INCOMING_VALUES0* inFixedValues, const FWPS_INCOMING_METADATA_VALUES0* inMetaValues, void* layerData, const void* classifyContext, const FWPS_FILTER1* filter, UINT64 flowContext, FWPS_CLASSIFY_OUT0* classifyOut) 
{
	classifyOut->actionType = FWP_ACTION_PERMIT;
	classifyOut->rights |= FWPS_RIGHT_ACTION_WRITE;
}
void NTAPI DriverDatagramDataInjectComplete(_In_ void* context,_Inout_ NET_BUFFER_LIST* netBufferList,_In_ BOOLEAN dispatchLevel) //Deprecated
{
	if (!NT_SUCCESS(netBufferList->Status))
	DbgPrint("NNTWfpProxyCore Error in InBoundDataInject:%x\n", netBufferList->Status);
	FwpsFreeCloneNetBufferList(netBufferList, 0);
}
NTSTATUS WfpOpenEngine()
{
	return FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &EngineHandle);
}
NTSTATUS WfpCreateProvider() 
{
	FWPM_PROVIDER Provider{0};
	Provider.providerKey = NNT_WFP_NET_PROVIDER_GUID;
	Provider.displayData.name = L"NNTWfpRedirect Provider";
	return FwpmProviderAdd(EngineHandle, &Provider, NULL);
	
}
NTSTATUS WfpRegisterCallout()
{
	FWPS_CALLOUT Callout = { 0 };
	Callout.calloutKey = NNT_WFP_NET_OUTBOUND_CALLOUT_GUID;
	Callout.flags = 0;
	Callout.classifyFn = (FWPS_CALLOUT_CLASSIFY_FN3)OutBoundConnectFilterCallBack;
	Callout.notifyFn = (FWPS_CALLOUT_NOTIFY_FN3)NotifyCallBack;
	Callout.flowDeleteFn = FlowDeleteCallBack;
	NTSTATUS Status= FwpsCalloutRegister(DeviceObject, &Callout, &RegCalloutId);
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}
	Callout.calloutKey = NNT_WFP_NET_INBOUND_CALLOUT_GUID;
	Callout.classifyFn = (FWPS_CALLOUT_CLASSIFY_FN3)InBoundConnectFilterCallBack;
	return FwpsCalloutRegister(DeviceObject, &Callout, &RegCalloutId);
}
NTSTATUS WfpAddCallout()
{
	FWPM_CALLOUT Callout = { 0 };
	Callout.flags = 0;
	Callout.displayData.name = L"NNTWfpProxyOutBoundCallout";
	Callout.displayData.description = L"This NNTWfpProxyOutBoundCallout!";
	Callout.providerKey = (GUID*)&NNT_WFP_NET_PROVIDER_GUID;
	Callout.calloutKey = NNT_WFP_NET_OUTBOUND_CALLOUT_GUID;
	Callout.applicableLayer = FWPM_LAYER_ALE_CONNECT_REDIRECT_V4;
	NTSTATUS Status= FwpmCalloutAdd(EngineHandle, &Callout, NULL, &AddCalloutId);
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}
	Callout.calloutKey = NNT_WFP_NET_INBOUND_CALLOUT_GUID;
	Callout.displayData.name = L"NNTWfpProxyInBoundCallout";
	Callout.displayData.description = L"This NNTWfpProxyInBoundCallout!";
	Callout.applicableLayer = FWPM_LAYER_DATAGRAM_DATA_V4;
	return FwpmCalloutAdd(EngineHandle, &Callout, NULL, &AddCalloutId);
}

NTSTATUS WfpAddSublayer()
{
	FWPM_SUBLAYER sublayer = { 0 };
	sublayer.displayData.name = L"NNTWfpProxySubLayer";
	sublayer.displayData.description = L"This NNTWfpProxySubLayer";
	sublayer.subLayerKey = NNT_WFP_NET_SUBLAYER_GUID;
	sublayer.providerKey = (GUID*)&NNT_WFP_NET_PROVIDER_GUID;
	sublayer.weight = MAXUINT16;
	return FwpmSubLayerAdd(EngineHandle, &sublayer, NULL);
}

NTSTATUS WfpAddFilter()
{
	FWPM_FILTER filter = { 0 };
	FWPM_FILTER_CONDITION condition[1] = { 0 };
	FWP_V4_ADDR_AND_MASK AddrandMask = { 0 };

	filter.displayData.name = L"NNTWfpProxyOutBoundFilterCalloutName";
	filter.displayData.description = L"This NNTWfpProxyOutBoundFilterCalloutName";
	filter.layerKey = FWPM_LAYER_ALE_CONNECT_REDIRECT_V4;
	filter.subLayerKey = NNT_WFP_NET_SUBLAYER_GUID;
	filter.weight.type = FWP_EMPTY;
	filter.numFilterConditions = 0;
	filter.filterCondition = NULL;
	filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
	filter.action.calloutKey = NNT_WFP_NET_OUTBOUND_CALLOUT_GUID;
	filter.filterKey = NNT_WFP_NET_OUTBOUND_FILTER_GUID;
	filter.providerKey = (GUID*)&NNT_WFP_NET_PROVIDER_GUID;
	NTSTATUS Status = FwpmFilterAdd(EngineHandle, &filter, NULL, &FilterId);
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}
	filter.displayData.name = L"NNTWfpProxyInBoundFilterCalloutName";
	filter.displayData.description = L"This NNTWfpProxyInBoundFilterCalloutName";
	filter.layerKey = FWPM_LAYER_DATAGRAM_DATA_V4;
	filter.action.calloutKey = NNT_WFP_NET_INBOUND_CALLOUT_GUID;
	filter.filterKey = NNT_WFP_NET_INBOUND_FILTER_GUID;
	return FwpmFilterAdd(EngineHandle, &filter, NULL, &FilterId);
}

NTSTATUS InitializeWfp()
{
	NTSTATUS Status;
	if (!NT_SUCCESS(Status = FwpsInjectionHandleCreate(AF_INET, FWPS_INJECTION_TYPE_TRANSPORT, &InjectHandle)))
	{
		UnInitWfp();
		return Status;
	}
	if (!NT_SUCCESS(Status = WfpOpenEngine()))
	{
		UnInitWfp();
		return Status;
	}
	if (!NT_SUCCESS(Status = WfpCreateProvider()))
	{
		UnInitWfp();
		return Status;
	}
	if (!NT_SUCCESS(Status = WfpRegisterCallout()))
	{
		UnInitWfp();
		return Status;
	}
	if (!NT_SUCCESS(Status = WfpAddCallout()))
	{
		UnInitWfp();
		return Status;
	}

	if (!NT_SUCCESS(Status = WfpAddSublayer()))
	{
		UnInitWfp();
		return Status;
	}
	if (!NT_SUCCESS(Status = WfpAddFilter()))
	{
		UnInitWfp();
		return Status;
	}
	Status = FwpsRedirectHandleCreate0(&NNT_WFP_NET_PROVIDER_GUID, 0, &RedirectHandle);
	if (!NT_SUCCESS(Status))
	{
		UnInitWfp();
		return Status;
	}
	return STATUS_SUCCESS;
}
VOID UnInitWfp()
{
	NTSTATUS Status;
	if (EngineHandle)
	{
		Status = FwpmFilterDeleteByKey(EngineHandle, &NNT_WFP_NET_OUTBOUND_FILTER_GUID);
		if (!NT_SUCCESS(Status)) 
		{
			DbgPrint("DeleteFilter Failed Status=%x\n",Status);
		}
		Status = FwpmFilterDeleteByKey(EngineHandle, &NNT_WFP_NET_INBOUND_FILTER_GUID);
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("DeleteFilter Failed Status=%x\n", Status);
		}
		Status = FwpmCalloutDeleteByKey(EngineHandle, &NNT_WFP_NET_OUTBOUND_CALLOUT_GUID);
		if(!NT_SUCCESS(Status))
		{
			DbgPrint("DeleteCallout Failed Status=%x\n", Status);
		}
		Status = FwpmCalloutDeleteByKey(EngineHandle, &NNT_WFP_NET_INBOUND_CALLOUT_GUID);
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("DeleteCallout Failed Status=%x\n", Status);
		}
		Status = FwpmSubLayerDeleteByKey(EngineHandle, &NNT_WFP_NET_SUBLAYER_GUID);
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("DeleteSublayer Failed Status=%x\n", Status);
		}
		if (RedirectHandle)
		{
			FwpsRedirectHandleDestroy(RedirectHandle);
			RedirectHandle = 0;
		}
		Status = FwpmProviderDeleteByKey(EngineHandle, &NNT_WFP_NET_PROVIDER_GUID);
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("FwpmProviderDeleteByKey Failed Status=%x\n", Status);
		}
		Status=FwpmEngineClose(EngineHandle);
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("EngineClose Failed Status=%x\n", Status);
		}
		EngineHandle = 0;
		Status = FwpsCalloutUnregisterByKey(&NNT_WFP_NET_OUTBOUND_CALLOUT_GUID);
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("CalloutUnregisterByKey Failed Status=%x\n", Status);
		}
		Status = FwpsCalloutUnregisterByKey(&NNT_WFP_NET_INBOUND_CALLOUT_GUID);
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("CalloutUnregisterByKey Failed Status=%x\n", Status);
		}
		if (InjectHandle)
		{
			Status = FwpsInjectionHandleDestroy(InjectHandle);
			if (!NT_SUCCESS(Status))
			{
				DbgPrint("FwpsInjectionHandleDestroy Failed Status=%x\n", Status);
			}
		}
	}
}
