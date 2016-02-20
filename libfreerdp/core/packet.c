/**
* FreeRDP: A Remote Desktop Protocol Implementation
* Packet Capture & Replay API
*
* Copyright 2016 Marc-Andre Moreau <marcandre.moreau@gmail.com>
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <freerdp/log.h>
#include <freerdp/packet.h>

#include <winpr/crt.h>
#include <winpr/print.h>
#include <winpr/stream.h>
#include <winpr/winsock.h>

#include "tcp.h"
#include "rdp.h"
#include "client.h"

#define TAG FREERDP_TAG("core")

/* PCAP BIO */

struct _WINPR_BIO_PCAP
{
	rdpContext* context;
	HANDLE event;
	rdpPcap* pcap;
	char* filename;
	UINT32 poffset;
	UINT32 plength;
	UINT32 srcAddress;
	UINT32 dstAddress;
	pcap_record record;
	rdpEthHeader eth;
	rdpIPv4Header ipv4;
	rdpTcpHeader tcp;
	wStream* cs;
};
typedef struct _WINPR_BIO_PCAP WINPR_BIO_PCAP;

int freerdp_packet_receive_channel_data(freerdp* instance, UINT16 channelId, BYTE* data, int dataSize, int flags, int totalSize)
{
	UINT32 index;
	rdpMcs* mcs;
	rdpChannels* channels;
	rdpMcsChannel* channel = NULL;
	CHANNEL_OPEN_DATA* pChannelOpenData;
	rdpContext* context = instance->context;
	rdpSettings* settings = context->settings;

	mcs = instance->context->rdp->mcs;
	channels = instance->context->channels;

	if (!channels || !mcs)
		return 1;

	for (index = 0; index < mcs->channelCount; index++)
	{
		if (mcs->channels[index].ChannelId == channelId)
		{
			channel = &mcs->channels[index];
			break;
		}
	}

	if (!channel)
		return 1;

	if (!strcmp(channel->Name, "drdynvc"))
	{
		pChannelOpenData = freerdp_channels_find_channel_open_data_by_name(channels, channel->Name);

		if (!pChannelOpenData)
			return 1;

		if (pChannelOpenData->pChannelOpenEventProc)
		{
			pChannelOpenData->pChannelOpenEventProc(pChannelOpenData->OpenHandle,
				CHANNEL_EVENT_DATA_RECEIVED, data, dataSize, totalSize, flags);
		}
	}

	return 0;
}

int freerdp_packet_client_to_server(rdpContext* context, wStream* s, UINT32 timestamp)
{
	UINT32 index;
	rdpRdp* rdp = context->rdp;
	rdpMcs* mcs = rdp->mcs;
	rdpSettings* settings = context->settings;

	if (rdp->state == CONNECTION_STATE_MCS_CONNECT)
	{
		UINT32 options;
		const char* name;

		mcs_recv_connect_initial(mcs, s);

		settings->ChannelCount = mcs->channelCount;

		settings->DynamicChannelCount = 0;
		settings->SupportDynamicChannels = FALSE;

		for (index = 0; index < mcs->channelCount; index++)
		{
			name = mcs->channels[index].Name;
			options = mcs->channels[index].options;

			CopyMemory(settings->ChannelDefArray[index].name, name, 8);
			settings->ChannelDefArray[index].options = options;

			WLog_INFO(TAG, " %s", name);

			if (!strcmp(name, "drdynvc"))
				settings->SupportDynamicChannels = TRUE;
			else if (!strcmp(name, "encomsp"))
				settings->EncomspVirtualChannel = TRUE;
			else if (!strcmp(name, "remdesk"))
				settings->RemdeskVirtualChannel = TRUE;
		}

		mcs_initialize_client_channels(mcs, settings);

		if (settings->SupportDynamicChannels)
		{
			settings->SupportGraphicsPipeline = TRUE;
		}
		else
		{
			settings->SupportGraphicsPipeline = FALSE;
			settings->RemoteFxCodec = TRUE;
		}
	}

	return 1;
}

static int transport_bio_pcap_init(BIO* bio, const char* filename);
static int transport_bio_pcap_uninit(BIO* bio);

static BOOL transport_bio_pcap_read_ethernet_header(FILE* fp, rdpEthHeader* ethernet)
{
	wStream* s;
	BYTE buffer[14];

	if (!fp || !ethernet)
		return FALSE;

	if (fread(buffer, 14, 1, fp) != 1)
		return FALSE;

	s = Stream_New(buffer, 14);

	if (!s)
		return FALSE;
	
	Stream_Read(s, ethernet->Destination, 6);
	Stream_Read(s, ethernet->Source, 6);
	Stream_Read_UINT16_BE(s, ethernet->Type);
	
	Stream_Free(s, FALSE);

	return TRUE;
}

static BOOL transport_bio_pcap_read_ipv4_header(FILE* fp, rdpIPv4Header* ipv4)
{
	wStream* s;
	BYTE bytes8;
	UINT16 bytes16;
	BYTE buffer[20];

	if (!fp || !ipv4)
		return FALSE;

	if (fread(buffer, 20, 1, fp) != 1)
		return FALSE;

	s = Stream_New(buffer, 20);
	
	if (!s)
		return FALSE;

	Stream_Read_UINT8(s, bytes8);
	ipv4->Version = (bytes8 >> 4) & 0x0F;
	ipv4->InternetHeaderLength = bytes8 & 0x0F;

	Stream_Read_UINT8(s, ipv4->TypeOfService);
	Stream_Read_UINT16_BE(s, ipv4->TotalLength);
	Stream_Read_UINT16_BE(s, ipv4->Identification);
	
	Stream_Read_UINT16_BE(s, bytes16);
	ipv4->InternetProtocolFlags = (bytes16 >> 13) & 0x03;
	ipv4->FragmentOffset = bytes16 & 0x1FFF;

	Stream_Read_UINT8(s, ipv4->TimeToLive);
	Stream_Read_UINT8(s, ipv4->Protocol);
	Stream_Read_UINT16(s, ipv4->HeaderChecksum);
	Stream_Read_UINT32_BE(s, ipv4->SourceAddress);
	Stream_Read_UINT32_BE(s, ipv4->DestinationAddress);
	
	Stream_Rewind(s, 10);
	Stream_Read_UINT16(s, ipv4->HeaderChecksum);
	Stream_Seek(s, 8);
	
	Stream_Free(s, FALSE);
	
	return TRUE;
}

static BOOL transport_bio_pcap_read_tcp_header(FILE* fp, rdpTcpHeader* tcp)
{
	wStream* s;
	BYTE bytes8;
	BYTE buffer[20];

	if (!fp || !tcp)
		return FALSE;

	if (fread(buffer, 20, 1, fp) != 1)
		return FALSE;

	s = Stream_New(buffer, 20);
	
	if (!s)
		return FALSE;

	Stream_Read_UINT16_BE(s, tcp->SourcePort);
	Stream_Read_UINT16_BE(s, tcp->DestinationPort);
	Stream_Read_UINT32_BE(s, tcp->SequenceNumber);
	Stream_Read_UINT32_BE(s, tcp->AcknowledgementNumber);
	
	Stream_Read_UINT8(s, bytes8);
	tcp->Offset = (bytes8 >> 4) & 0x0F;
	tcp->Reserved = bytes8 & 0x0F;

	Stream_Read_UINT8(s, tcp->TcpFlags);
	Stream_Read_UINT16_BE(s, tcp->Window);
	Stream_Read_UINT16_BE(s, tcp->Checksum);
	Stream_Read_UINT16_BE(s, tcp->UrgentPointer);

	Stream_Free(s, FALSE);

	return TRUE;
}

BOOL transport_bio_pcap_process_first_packet(BIO* bio)
{
	wStream* s;
	BYTE li = 0;
	BYTE code = 0;
	UINT16 length;
	BOOL client = TRUE;
	UINT32 protocol = PROTOCOL_RDP;
	WINPR_BIO_PCAP* ptr = (WINPR_BIO_PCAP*) bio->ptr;
	rdpContext* context = ptr->context;
	rdpSettings* settings = context->settings;
	rdpRdp* rdp = context->rdp;
	rdpNego* nego = rdp->nego;

	s = Stream_New(NULL, ptr->plength);

	if (!s)
		return FALSE;

	fread(Stream_Buffer(s), 1, ptr->plength, ptr->pcap->fp);
	fseek(ptr->pcap->fp, -1 * ptr->plength, SEEK_CUR);
	Stream_SetLength(s, ptr->plength);
	Stream_SetPosition(s, 0);

	settings->RdpSecurity = TRUE;
	settings->TlsSecurity = FALSE;
	settings->NlaSecurity = FALSE;

	length = tpkt_read_header(s);

	if (length && tpdu_read_header(s, &code, &li))
	{
		BYTE type;

		if (code == X224_TPDU_CONNECTION_REQUEST)
		{
			if (nego_read_request_token_or_cookie(nego, s))
			{
				if (Stream_GetRemainingLength(s) >= 8)
				{
					Stream_Read_UINT8(s, type); /* Type */

					if (type == TYPE_RDP_NEG_REQ)
					{
						Stream_Seek_UINT8(s); /* flags */
						Stream_Seek_UINT16(s); /* length */
						Stream_Read_UINT32(s, protocol); /* selectedProtocol */
					}
				}
			}

			client = TRUE;
		}
		else if (code == X224_TPDU_CONNECTION_CONFIRM)
		{
			if (li > 6)
			{
				Stream_Read_UINT8(s, type); /* Type */

				if (type == TYPE_RDP_NEG_RSP)
				{
					Stream_Seek_UINT8(s); /* flags */
					Stream_Seek_UINT16(s); /* length */
					Stream_Read_UINT32(s, protocol); /* selectedProtocol */
				}
			}

			client = FALSE;
		}
	}

	if (protocol == PROTOCOL_NLA)
	{
		settings->RdpSecurity = FALSE;
		settings->TlsSecurity = FALSE;
		settings->NlaSecurity = TRUE;
	}
	else if (protocol == PROTOCOL_TLS)
	{
		settings->RdpSecurity = FALSE;
		settings->TlsSecurity = TRUE;
		settings->NlaSecurity = FALSE;
	}
	else if (protocol == PROTOCOL_RDP)
	{
		settings->RdpSecurity = TRUE;
		settings->TlsSecurity = FALSE;
		settings->NlaSecurity = FALSE;
	}

	nego_enable_rdp(nego, settings->RdpSecurity);
	nego_enable_tls(nego, settings->TlsSecurity);
	nego_enable_nla(nego, settings->NlaSecurity);

	return client;
}

static BOOL transport_bio_pcap_next(BIO* bio)
{
	WINPR_BIO_PCAP* ptr = (WINPR_BIO_PCAP*) bio->ptr;
	rdpContext* context = ptr->context;
	rdpSettings* settings = context->settings;

	if (!ptr->plength)
	{
		if (!pcap_has_next_record(ptr->pcap))
			return FALSE;

		if (!pcap_get_next_record_header(ptr->pcap, &ptr->record))
			return FALSE;

		ptr->poffset = 0;
		ptr->plength = ptr->record.length;

		if (ptr->plength < 54)
			return FALSE;

		if (!transport_bio_pcap_read_ethernet_header(ptr->pcap->fp, &ptr->eth))
			return FALSE;

		if (!transport_bio_pcap_read_ipv4_header(ptr->pcap->fp, &ptr->ipv4))
			return FALSE;

		if (!transport_bio_pcap_read_tcp_header(ptr->pcap->fp, &ptr->tcp))
			return FALSE;

		ptr->poffset = 0;
		ptr->plength -= 54;

		if (!ptr->srcAddress)
		{
			if (transport_bio_pcap_process_first_packet(bio))
			{
				/* first packet is sent by the client */
				ptr->srcAddress = ptr->ipv4.SourceAddress;
				ptr->dstAddress = ptr->ipv4.DestinationAddress;
			}
			else
			{
				/* first packet is sent by the server */
				ptr->srcAddress = ptr->ipv4.DestinationAddress;
				ptr->dstAddress = ptr->ipv4.SourceAddress;
			}
		}

		if (ptr->srcAddress == ptr->ipv4.SourceAddress)
		{
			Stream_EnsureCapacity(ptr->cs, ptr->plength);
			fread(Stream_Buffer(ptr->cs), 1, ptr->plength, ptr->pcap->fp);
			Stream_SetLength(ptr->cs, ptr->plength);
			Stream_SetPosition(ptr->cs, 0);
			ptr->poffset = 0;
			ptr->plength = 0;

			freerdp_packet_client_to_server(ptr->context, ptr->cs, 0);

			return transport_bio_pcap_next(bio);
		}

		return TRUE;
	}

	return TRUE;
}

static long transport_bio_pcap_callback(BIO* bio, int mode, const char* argp, int argi, long argl, long ret)
{
	return 1;
}

static int transport_bio_pcap_write(BIO* bio, const char* buf, int size)
{
	int status = 0;
	WINPR_BIO_PCAP* ptr = (WINPR_BIO_PCAP*) bio->ptr;

	if (!buf)
		return 0;

	BIO_clear_flags(bio, BIO_FLAGS_WRITE);

	status = size;

	BIO_set_flags(bio, (BIO_FLAGS_WRITE | BIO_FLAGS_SHOULD_RETRY));

	return status;
}

static int transport_bio_pcap_read(BIO* bio, char* buf, int size)
{
	int status = 0;
	WINPR_BIO_PCAP* ptr = (WINPR_BIO_PCAP*) bio->ptr;

	if (!buf)
		return 0;

	BIO_clear_flags(bio, BIO_FLAGS_READ);

	if (!transport_bio_pcap_next(bio))
		goto failure;

	status = ptr->plength - ptr->poffset;

	if (status > size)
		status = size;

	status = fread(buf, 1, status, ptr->pcap->fp);

	if (status < 0)
		goto failure;

	ptr->poffset += status;

	if (ptr->poffset == ptr->plength)
	{
		ptr->poffset = 0;
		ptr->plength = 0;
	}

	BIO_set_flags(bio, (BIO_FLAGS_READ | BIO_FLAGS_SHOULD_RETRY));

	return status;

failure:
	BIO_clear_flags(bio, BIO_FLAGS_SHOULD_RETRY);
	ResetEvent(ptr->event);
	return -1;
}

static int transport_bio_pcap_puts(BIO* bio, const char* str)
{
	return 1;
}

static int transport_bio_pcap_gets(BIO* bio, char* str, int size)
{
	return 1;
}

static long transport_bio_pcap_ctrl(BIO* bio, int cmd, long arg1, void* arg2)
{
	int status = -1;
	WINPR_BIO_PCAP* ptr = (WINPR_BIO_PCAP*) bio->ptr;

	if (cmd == BIO_C_SET_SOCKET)
	{
		return 1;
	}
	else if (cmd == BIO_C_GET_SOCKET)
	{
		return 1;
	}
	else if (cmd == BIO_C_GET_EVENT)
	{
		if (!bio->init || !arg2)
			return 0;

		*((ULONG_PTR*) arg2) = (ULONG_PTR) ptr->event;

		return 1;
	}
	else if (cmd == BIO_C_SET_NONBLOCK)
	{
		return 1;
	}
	else if (cmd == BIO_C_WAIT_READ)
	{
		return 1;
	}
	else if (cmd == BIO_C_WAIT_WRITE)
	{
		return 1;
	}
	else if (cmd == BIO_C_SET_CONNECT)
	{
		if (arg1 == 0)
		{
			transport_bio_pcap_uninit(bio);
			transport_bio_pcap_init(bio, (char*) arg2);
		}
	}
	else if (cmd == BIO_C_SET_RDP_CONTEXT)
	{
		rdpContext* context = (rdpContext*) arg2;
		freerdp* instance = context->instance;

		ptr->context = context;
		instance->ReceiveChannelData = freerdp_packet_receive_channel_data;
	}

	switch (cmd)
	{
		case BIO_C_SET_FD:
			status = 1;
			break;

		case BIO_C_GET_FD:
			status = 1;
			break;

		case BIO_CTRL_GET_CLOSE:
			status = bio->shutdown;
			break;

		case BIO_CTRL_SET_CLOSE:
			bio->shutdown = (int) arg1;
			status = 1;
			break;

		case BIO_CTRL_DUP:
			status = 1;
			break;

		case BIO_CTRL_FLUSH:
			status = 1;
			break;

		default:
			status = 0;
			break;
	}

	return status;
}

static int transport_bio_pcap_init(BIO* bio, const char* filename)
{
	WINPR_BIO_PCAP* ptr = (WINPR_BIO_PCAP*) bio->ptr;

	ptr->cs = Stream_New(NULL, 1024);

	if (!ptr->cs)
		return 0;

	ptr->filename = _strdup(filename);
	ptr->pcap = pcap_open(ptr->filename, FALSE);

	bio->flags = BIO_FLAGS_SHOULD_RETRY;
	bio->init = 1;

	ptr->event = CreateEvent(NULL, TRUE, FALSE, NULL);

	if (!ptr->event)
		return 0;

	SetEvent(ptr->event);

	return 1;
}

static int transport_bio_pcap_uninit(BIO* bio)
{
	WINPR_BIO_PCAP* ptr = (WINPR_BIO_PCAP*) bio->ptr;

	if (bio->init)
	{
		pcap_close(ptr->pcap);
		ptr->pcap = NULL;
	}

	if (ptr->event)
	{
		CloseHandle(ptr->event);
		ptr->event = NULL;
	}

	if (ptr->cs)
	{
		Stream_Free(ptr->cs, TRUE);
		ptr->cs = NULL;
	}

	bio->init = 0;
	bio->flags = 0;

	return 1;
}

static int transport_bio_pcap_new(BIO* bio)
{
	WINPR_BIO_PCAP* ptr;

	bio->init = 0;
	bio->ptr = NULL;
	bio->flags = BIO_FLAGS_SHOULD_RETRY;

	ptr = (WINPR_BIO_PCAP*) calloc(1, sizeof(WINPR_BIO_PCAP));

	if (!ptr)
		return 0;

	bio->ptr = ptr;

	return 1;
}

static int transport_bio_pcap_free(BIO* bio)
{
	if (!bio)
		return 0;

	transport_bio_pcap_uninit(bio);

	if (bio->ptr)
	{
		free(bio->ptr);
		bio->ptr = NULL;
	}

	return 1;
}

static BIO_METHOD transport_bio_pcap_methods =
{
	BIO_TYPE_PCAP,
	"PCAP",
	transport_bio_pcap_write,
	transport_bio_pcap_read,
	transport_bio_pcap_puts,
	transport_bio_pcap_gets,
	transport_bio_pcap_ctrl,
	transport_bio_pcap_new,
	transport_bio_pcap_free,
	NULL,
};

BIO_METHOD* BIO_s_pcap(void)
{
	return &transport_bio_pcap_methods;
}
