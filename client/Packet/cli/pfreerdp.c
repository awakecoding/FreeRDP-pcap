
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "packet.h"

#include <winpr/windows.h>

#include <freerdp/client/file.h>
#include <freerdp/client/cmdline.h>
#include <freerdp/client/channels.h>
#include <freerdp/channels/channels.h>

int main(int argc, char** argv)
{
	int status;
	HANDLE thread;
	DWORD dwExitCode;
	rdpContext* context;
	rdpSettings* settings;
	RDP_CLIENT_ENTRY_POINTS clientEntryPoints;

	ZeroMemory(&clientEntryPoints, sizeof(RDP_CLIENT_ENTRY_POINTS));
	clientEntryPoints.Size = sizeof(RDP_CLIENT_ENTRY_POINTS);
	clientEntryPoints.Version = RDP_CLIENT_INTERFACE_VERSION;

	RdpClientEntry(&clientEntryPoints);

	context = freerdp_client_context_new(&clientEntryPoints);

	settings = context->settings;

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
