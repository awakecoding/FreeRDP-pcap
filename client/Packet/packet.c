/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Windows Client
 *
 * Copyright 2009-2011 Jay Sorg
 * Copyright 2010-2011 Vic Lee
 * Copyright 2010-2011 Marc-Andre Moreau <marcandre.moreau@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	 http://www.apache.org/licenses/LICENSE-2.0
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

#include <winpr/windows.h>

#include <winpr/crt.h>
#include <winpr/image.h>

#include <freerdp/log.h>
#include <freerdp/freerdp.h>
#include <freerdp/gdi/gfx.h>
#include <freerdp/gdi/region.h>
#include <freerdp/codec/region.h>
#include <freerdp/client/cmdline.h>
#include <freerdp/client/channels.h>

#include "packet.h"

#define TAG CLIENT_TAG("packet")

void pf_OnChannelConnectedEventHandler(rdpContext* context, ChannelConnectedEventArgs* e)
{
	WLog_WARN(TAG, "OnChannelConnectedEventHandler: %s", e->name);

	if (!strcmp(e->name, RDPGFX_DVC_CHANNEL_NAME))
	{
		gdi_graphics_pipeline_init(context->gdi, (RdpgfxClientContext*) e->pInterface);
	}
}

void pf_OnChannelDisconnectedEventHandler(rdpContext* context, ChannelDisconnectedEventArgs* e)
{
	WLog_WARN(TAG, "OnChannelDisconnectedEventHandler: %s", e->name);

	if (!strcmp(e->name, RDPGFX_DVC_CHANNEL_NAME))
	{
		gdi_graphics_pipeline_uninit(context->gdi, (RdpgfxClientContext*) e->pInterface);
	}
}

BOOL pf_begin_paint(pfContext* pfc)
{
	rdpGdi* gdi = ((rdpContext*) pfc)->gdi;
	gdi->primary->hdc->hwnd->invalid->null = 1;
	gdi->primary->hdc->hwnd->ninvalid = 0;
	return TRUE;
}

BOOL pf_end_paint(pfContext* pfc)
{
	wImage img;
	rdpGdi* gdi;
	HGDI_RGN invalid;
	char filename[256];
	rdpContext* context = (rdpContext*) pfc;

	gdi = context->gdi;
	invalid = gdi->primary->hdc->hwnd->invalid;

	if (invalid->null)
		return TRUE;

	WLog_DBG(TAG, "OnPaint: %d %d %d %d", invalid->x, invalid->y, invalid->w, invalid->h);

	sprintf_s(filename, sizeof(filename) - 1, "rdp_%04d.bmp", pfc->frameIndex++);

	ZeroMemory(&img, sizeof(wImage));
	img.type = WINPR_IMAGE_BITMAP;
	img.width = gdi->width;
	img.height = gdi->height;
	img.data = gdi->primary_buffer;
	img.scanline = gdi->width * 4;
	img.bitsPerPixel = 32;
	img.bytesPerPixel = 4;
	
	winpr_image_write(&img, filename);

	return TRUE;
}

BOOL pf_desktop_resize(pfContext* pfc)
{
	rdpContext* context = (rdpContext*) pfc;
	rdpSettings* settings = context->settings;

	if (!gdi_resize(context->gdi, settings->DesktopWidth, settings->DesktopHeight))
		return FALSE;

	return TRUE;
}

BOOL pf_pre_connect(freerdp* instance)
{
	rdpContext* context = instance->context;
	rdpSettings* settings = context->settings;
	rdpChannels* channels = context->channels;

	settings->AsyncInput = FALSE;
	settings->AsyncUpdate = FALSE;
	settings->AsyncTransport = FALSE;
	settings->AsyncChannels = FALSE;

	settings->OsMajorType = OSMAJORTYPE_WINDOWS;
	settings->OsMinorType = OSMINORTYPE_WINDOWS_NT;
	settings->OrderSupport[NEG_DSTBLT_INDEX] = TRUE;
	settings->OrderSupport[NEG_PATBLT_INDEX] = TRUE;
	settings->OrderSupport[NEG_SCRBLT_INDEX] = TRUE;
	settings->OrderSupport[NEG_OPAQUE_RECT_INDEX] = TRUE;
	settings->OrderSupport[NEG_DRAWNINEGRID_INDEX] = FALSE;
	settings->OrderSupport[NEG_MULTIDSTBLT_INDEX] = FALSE;
	settings->OrderSupport[NEG_MULTIPATBLT_INDEX] = FALSE;
	settings->OrderSupport[NEG_MULTISCRBLT_INDEX] = FALSE;
	settings->OrderSupport[NEG_MULTIOPAQUERECT_INDEX] = TRUE;
	settings->OrderSupport[NEG_MULTI_DRAWNINEGRID_INDEX] = FALSE;
	settings->OrderSupport[NEG_LINETO_INDEX] = TRUE;
	settings->OrderSupport[NEG_POLYLINE_INDEX] = TRUE;
	settings->OrderSupport[NEG_MEMBLT_INDEX] = TRUE;
	settings->OrderSupport[NEG_MEM3BLT_INDEX] = FALSE;
	settings->OrderSupport[NEG_SAVEBITMAP_INDEX] = FALSE;
	settings->OrderSupport[NEG_GLYPH_INDEX_INDEX] = FALSE;
	settings->OrderSupport[NEG_FAST_INDEX_INDEX] = FALSE;
	settings->OrderSupport[NEG_FAST_GLYPH_INDEX] = FALSE;
	settings->OrderSupport[NEG_POLYGON_SC_INDEX] = FALSE;
	settings->OrderSupport[NEG_POLYGON_CB_INDEX] = FALSE;
	settings->OrderSupport[NEG_ELLIPSE_SC_INDEX] = FALSE;
	settings->OrderSupport[NEG_ELLIPSE_CB_INDEX] = FALSE;

	settings->GlyphSupportLevel = GLYPH_SUPPORT_FULL;

	settings->ColorDepth = 32;
	settings->RemoteFxCodec = TRUE;
	settings->SurfaceFrameMarkerEnabled = TRUE;
	settings->FrameMarkerCommandEnabled = TRUE;

	settings->ExternalTransport = TRUE;
	settings->ExternalSecurity = TRUE;
	settings->CompressionEnabled = FALSE;
	settings->IgnoreCertificate = TRUE;
	settings->ExternalCertificateManagement = TRUE;

	settings->SupportGraphicsPipeline = TRUE;

	context->cache = cache_new(settings);

	if (!context->cache)
		return FALSE;

	PubSub_SubscribeChannelConnected(context->pubSub,
		(pChannelConnectedEventHandler) pf_OnChannelConnectedEventHandler);

	PubSub_SubscribeChannelDisconnected(context->pubSub,
		(pChannelDisconnectedEventHandler) pf_OnChannelDisconnectedEventHandler);

	freerdp_channels_pre_connect(channels, instance);

	return TRUE;
}

BOOL pf_post_connect(freerdp* instance)
{
	rdpContext* context = instance->context;
	rdpSettings* settings = context->settings;
	rdpChannels* channels = context->channels;
	rdpUpdate* update = context->update;

	if (!gdi_init(instance, CLRCONV_ALPHA | CLRBUF_32BPP, NULL))
		return FALSE;

	update->BeginPaint = (pBeginPaint) pf_begin_paint;
	update->EndPaint = (pEndPaint) pf_end_paint;
	update->DesktopResize = (pDesktopResize) pf_desktop_resize;

	freerdp_client_load_addins(channels, settings);

	if (freerdp_channels_post_connect(channels, instance) < 0)
		return FALSE;

	return TRUE;
}

void pf_post_disconnect(freerdp* instance)
{
	//gdi_free(instance);
}

static BOOL pf_authenticate(freerdp* instance, char** username, char** password, char** domain)
{
	return TRUE;
}

static BOOL pf_gw_authenticate(freerdp* instance, char** username, char** password, char** domain)
{
	return TRUE;
}

int pf_verify_x509_certificate(freerdp* instance, BYTE* data, int length, const char* hostname, int port, DWORD flags)
{
	return 1;
}

int pf_logon_error_info(freerdp* instance, UINT32 data, UINT32 type)
{
	return 1;
}

DWORD WINAPI pf_client_thread(LPVOID lpParam)
{
	DWORD nCount;
	DWORD waitStatus;
	HANDLE handles[64];
	pfContext* pfc;
	freerdp* instance;
	rdpContext* context;

	context = (rdpContext*) lpParam;
	pfc = (pfContext*) context;
	instance = context->instance;

	if (!freerdp_connect(instance))
	{
		ExitThread(0);
		return 0;
	}

	while (1)
	{
		nCount = 0;
		handles[nCount++] = pfc->stopEvent;

		nCount += freerdp_get_event_handles(context, &handles[nCount], 64 - nCount);

		waitStatus = WaitForMultipleObjects(nCount, handles, FALSE, INFINITE);

		if (waitStatus == WAIT_FAILED)
			break;

		if (waitStatus == WAIT_OBJECT_0)
			break;

		if (!freerdp_check_event_handles(context))
			break;
	}

	ExitThread(0);
	return 0;
}

BOOL pfreerdp_client_global_init(void)
{
	return TRUE;
}

void pfreerdp_client_global_uninit(void)
{

}

BOOL pfreerdp_client_new(freerdp* instance, rdpContext* context)
{
	pfContext* pfc = (pfContext*) context;

	context->channels = freerdp_channels_new();

	if (!context->channels)
		return FALSE;

	instance->PreConnect = pf_pre_connect;
	instance->PostConnect = pf_post_connect;
	instance->PostDisconnect = pf_post_disconnect;
	instance->Authenticate = pf_authenticate;
	instance->GatewayAuthenticate = pf_gw_authenticate;
	instance->VerifyX509Certificate = pf_verify_x509_certificate;
	instance->LogonErrorInfo = pf_logon_error_info;

	pfc->instance = instance;
	pfc->settings = instance->settings;

	pfc->stopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	return TRUE;
}

void pfreerdp_client_free(freerdp* instance, rdpContext* context)
{
	pfContext* pfc = (pfContext*) context;

	if (!context)
		return;

	if (context->channels)
	{
		freerdp_channels_close(context->channels, instance);
		freerdp_channels_free(context->channels);
		context->channels = NULL;
	}

	if (context->cache)
	{
		cache_free(context->cache);
		context->cache = NULL;
	}

	if (pfc->stopEvent)
	{
		CloseHandle(pfc->stopEvent);
		pfc->stopEvent = NULL;
	}
}

int pfreerdp_client_start(rdpContext* context)
{
	pfContext* pfc = (pfContext*) context;

	pfc->thread = CreateThread(NULL, 0, pf_client_thread, (void*) context, 0, NULL);

	if (!pfc->thread)
		return -1;

	return 0;
}

int pfreerdp_client_stop(rdpContext* context)
{
	pfContext* pfc = (pfContext*) context;

	if (pfc->thread)
	{
		SetEvent(pfc->stopEvent);
		WaitForSingleObject(pfc->thread, INFINITE);
		CloseHandle(pfc->thread);
		pfc->thread = NULL;
	}

	return 0;
}

int RdpClientEntry(RDP_CLIENT_ENTRY_POINTS* pEntryPoints)
{
	pEntryPoints->Version = 1;
	pEntryPoints->Size = sizeof(RDP_CLIENT_ENTRY_POINTS_V1);

	pEntryPoints->GlobalInit = pfreerdp_client_global_init;
	pEntryPoints->GlobalUninit = pfreerdp_client_global_uninit;

	pEntryPoints->ContextSize = sizeof(pfContext);
	pEntryPoints->ClientNew = pfreerdp_client_new;
	pEntryPoints->ClientFree = pfreerdp_client_free;

	pEntryPoints->ClientStart = pfreerdp_client_start;
	pEntryPoints->ClientStop = pfreerdp_client_stop;

	return 0;
}
