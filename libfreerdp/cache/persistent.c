/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Persistent Bitmap Cache
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

#include <winpr/crt.h>
#include <winpr/stream.h>

#include <freerdp/freerdp.h>
#include <freerdp/constants.h>

#include <freerdp/log.h>
#include <freerdp/cache/persistent.h>

#define TAG FREERDP_TAG("cache.persistent")

#pragma pack(push, 1)

/* 20 bytes */

struct _PERSISTENT_CACHE_ENTRY_V2
{
	UINT64 key64;
	UINT16 width;
	UINT16 height;
	UINT32 size;
	UINT32 flags; /* 0x00000011 */
};
typedef struct _PERSISTENT_CACHE_ENTRY_V2 PERSISTENT_CACHE_ENTRY_V2;

/* 12 bytes */

struct _PERSISTENT_CACHE_HEADER_V3
{
	BYTE sig[8];
	UINT32 flags; /* 0x00000003, 0x00000006 */
};
typedef struct _PERSISTENT_CACHE_HEADER_V3 PERSISTENT_CACHE_HEADER_V3;

/* 12 bytes */

struct _PERSISTENT_CACHE_ENTRY_V3
{
	UINT64 key64;
	UINT16 width;
	UINT16 height;
};
typedef struct _PERSISTENT_CACHE_ENTRY_V3 PERSISTENT_CACHE_ENTRY_V3;

#pragma pack(pop)

int persistent_cache_read_v2(rdpPersistentCache* persistent)
{
	PERSISTENT_CACHE_ENTRY_V2 entry;

	while (1)
	{
		if (fread((void*) &entry, sizeof(PERSISTENT_CACHE_ENTRY_V2), 1, persistent->fp) != 1)
			break;

		if (fseek(persistent->fp, 0x4000, SEEK_CUR) != 0)
			break;

		persistent->count++;
	}

	return 1;
}

int persistent_cache_read_v3(rdpPersistentCache* persistent)
{
	PERSISTENT_CACHE_ENTRY_V3 entry;

	while (1)
	{
		if (fread((void*) &entry, sizeof(PERSISTENT_CACHE_ENTRY_V3), 1, persistent->fp) != 1)
			break;

		if (fseek(persistent->fp, (entry.width * entry.height * 4), SEEK_CUR) != 0)
			break;

		persistent->count++;
	}

	return 1;
}

int persistent_cache_open_read(rdpPersistentCache* persistent)
{
	BYTE sig[8];
	int status = 1;
	PERSISTENT_CACHE_HEADER_V3 header;

	persistent->fp = fopen(persistent->filename, "rb");

	if (!persistent->fp)
		return -1;

	if (fread(sig, 8, 1, persistent->fp) != 1)
		return -1;

	if (!strncmp(sig, "RDP8bmp", 8))
		persistent->version = 3;
	else
		persistent->version = 2;

	fseek(persistent->fp, 0, SEEK_SET);

	if (persistent->version == 3)
	{
		if (fread(&header, sizeof(PERSISTENT_CACHE_HEADER_V3), 1, persistent->fp) != 1)
			return -1;

		status = persistent_cache_read_v3(persistent);
	}
	else
	{
		status = persistent_cache_read_v2(persistent);
	}

	return status;
}

int persistent_cache_open_write(rdpPersistentCache* persistent)
{
	persistent->fp = fopen(persistent->filename, "w+b");

	if (!persistent->fp)
		return -1;

	return 1;
}

int persistent_cache_open(rdpPersistentCache* persistent, const char* filename, BOOL write, int version)
{
	persistent->write = write;

	persistent->filename = _strdup(filename);

	if (!persistent->filename)
		return -1;

	if (persistent->write)
	{
		persistent->version = version;
		return persistent_cache_open_write(persistent);
	}

	return persistent_cache_open_read(persistent);
}

int persistent_cache_close(rdpPersistentCache* persistent)
{
	if (persistent->fp)
	{
		fclose(persistent->fp);
		persistent->fp = NULL;
	}

	return 1;
}

rdpPersistentCache* persistent_cache_new()
{
	rdpPersistentCache* persistent;

	persistent = (rdpPersistentCache*) calloc(1, sizeof(rdpPersistentCache));

	if (!persistent)
		return NULL;

	return persistent;
}

void persistent_cache_free(rdpPersistentCache* persistent)
{
	if (!persistent)
		return;

	persistent_cache_close(persistent);

	free(persistent->filename);

	free(persistent);
}