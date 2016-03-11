
#ifndef FREERDP_CLIENT_PACKET_H
#define FREERDP_CLIENT_PACKET_H

#include <winpr/windows.h>

#include <freerdp/api.h>
#include <freerdp/freerdp.h>

typedef struct pf_context pfContext;

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*fnReplayFrame)(pfContext* pfc,
	BYTE* frameData, int frameStep, int frameWidth, int frameHeight,
	int changeX, int changeY, int changeWidth, int changeHeight,
	UINT64 frameTime, int frameIndex);

struct pf_context
{
	rdpContext context;
	DEFINE_RDP_CLIENT_COMMON();

	int frameIndex;
	HANDLE stopEvent;
	freerdp* instance;
	rdpSettings* settings;

	fnReplayFrame ReplayFrame;
};

/**
 * Client Interface
 */

FREERDP_API int RdpClientEntry(RDP_CLIENT_ENTRY_POINTS* pEntryPoints);

#ifdef __cplusplus
}
#endif

#endif /* FREERDP_CLIENT_PACKET_H */
