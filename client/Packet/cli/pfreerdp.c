
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "packet.h"

#include <winpr/crt.h>
#include <winpr/image.h>
#include <winpr/windows.h>

#include <freerdp/client/file.h>
#include <freerdp/client/cmdline.h>
#include <freerdp/client/channels.h>
#include <freerdp/channels/channels.h>

int pfreerdp_replay_frame(pfContext* pfc,
	BYTE* frameData, int frameStep, int frameWidth, int frameHeight,
	int changeX, int changeY, int changeWidth, int changeHeight,
	UINT64 frameTime, int frameIndex)
{
	wImage img;
	char filename[256];

	sprintf_s(filename, sizeof(filename) - 1, "rdp_%04d.bmp", frameIndex);

	ZeroMemory(&img, sizeof(wImage));
	img.type = WINPR_IMAGE_BITMAP;
	img.width = frameWidth;
	img.height = frameHeight;
	img.data = frameData;
	img.scanline = frameStep;
	img.bitsPerPixel = 32;
	img.bytesPerPixel = 4;

	winpr_image_write(&img, filename);

	return 1;
}

int main(int argc, char** argv)
{
	int status;
	HANDLE thread;
	DWORD dwExitCode;
	pfContext* pfc;
	rdpContext* context;
	rdpSettings* settings;
	RDP_CLIENT_ENTRY_POINTS clientEntryPoints;

	ZeroMemory(&clientEntryPoints, sizeof(RDP_CLIENT_ENTRY_POINTS));
	clientEntryPoints.Size = sizeof(RDP_CLIENT_ENTRY_POINTS);
	clientEntryPoints.Version = RDP_CLIENT_INTERFACE_VERSION;

	RdpClientEntry(&clientEntryPoints);

	context = freerdp_client_context_new(&clientEntryPoints);

	pfc = (pfContext*) context;
	settings = context->settings;

	pfc->ReplayFrame = pfreerdp_replay_frame;

	status = freerdp_client_settings_parse_command_line(settings, argc, argv, FALSE);

	status = freerdp_client_settings_command_line_status_print(settings, status, argc, argv);

	if (status)
	{
		freerdp_client_context_free(context);
		return 0;
	}

	freerdp_client_start(context);

	thread = freerdp_client_get_thread(context);

	WaitForSingleObject(thread, INFINITE);

	GetExitCodeThread(thread, &dwExitCode);

	freerdp_client_stop(context);

	freerdp_client_context_free(context);

	return 0;
}
