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

int persistent_cache_get_version(rdpPersistentCache* persistent)
{
	return persistent->version;
}

int persistent_cache_get_count(rdpPersistentCache* persistent)
{
	return persistent->count;
}

int persistent_cache_read_entry_v2(rdpPersistentCache* persistent, PERSISTENT_CACHE_ENTRY* entry)
{
	PERSISTENT_CACHE_ENTRY_V2 entry2;

	if (fread((void*) &entry2, sizeof(PERSISTENT_CACHE_ENTRY_V2), 1, persistent->fp) != 1)
		return -1;

	entry->key64 = entry2.key64;
	entry->width = entry2.width;
	entry->height = entry2.height;
	entry->size = entry2.width * entry2.height * 4;
	entry->flags = entry2.flags;

	entry->data = persistent->bmpData;

	if (fread((void*) entry->data, 0x4000, 1, persistent->fp) != 0)
		return -1;

	return 1;
}

int persistent_cache_write_entry_v2(rdpPersistentCache* persistent, PERSISTENT_CACHE_ENTRY* entry)
{
	int padding;
	PERSISTENT_CACHE_ENTRY_V2 entry2;

	if (!entry->flags)
		entry->flags = 0x00000011;

	entry2.key64 = entry->key64;
	entry2.width = entry->width;
	entry2.height = entry->height;
	entry2.size = entry->size;
	entry2.flags = entry->flags;

	if (fwrite((void*) &entry2, sizeof(PERSISTENT_CACHE_ENTRY_V2), 1, persistent->fp) != 1)
		return -1;

	if (fwrite((void*) entry->data, entry->size, 1, persistent->fp) != 1)
		return -1;

	if (0x4000 > entry->size)
	{
		padding = 0x4000 - entry->size;
		
		if (fwrite((void*) persistent->bmpData, padding, 1, persistent->fp) != 1)
			return -1;
	}

	persistent->count++;

	return 1;
}

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

int persistent_cache_read_entry_v3(rdpPersistentCache* persistent, PERSISTENT_CACHE_ENTRY* entry)
{
	PERSISTENT_CACHE_ENTRY_V3 entry3;

	if (fread((void*) &entry3, sizeof(PERSISTENT_CACHE_ENTRY_V3), 1, persistent->fp) != 1)
		return -1;

	entry->key64 = entry3.key64;
	entry->width = entry3.width;
	entry->height = entry3.height;
	entry->size = entry3.width * entry3.height * 4;
	entry->flags = 0;

	if (entry->size > persistent->bmpSize)
	{
		persistent->bmpSize = entry->size;
		persistent->bmpData = (BYTE*) realloc(persistent->bmpData, persistent->bmpSize);

		if (!persistent->bmpData)
			return -1;
	}

	entry->data = persistent->bmpData;

	if (fread((void*) entry->data, entry->size, 1, persistent->fp) != 1)
		return -1;

	return 1;
}

int persistent_cache_write_entry_v3(rdpPersistentCache* persistent, PERSISTENT_CACHE_ENTRY* entry)
{
	PERSISTENT_CACHE_ENTRY_V3 entry3;

	entry3.key64 = entry->key64;
	entry3.width = entry->width;
	entry3.height = entry->height;

	if (fwrite((void*) &entry3, sizeof(PERSISTENT_CACHE_ENTRY_V3), 1, persistent->fp) != 1)
		return -1;

	if (fwrite((void*) entry->data, entry->size, 1, persistent->fp) != 1)
		return -1;

	persistent->count++;

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

int persistent_cache_read_entry(rdpPersistentCache* persistent, PERSISTENT_CACHE_ENTRY* entry)
{
	if (persistent->version == 3)
		return persistent_cache_read_entry_v3(persistent, entry);
	else if (persistent->version == 2)
		return persistent_cache_read_entry_v2(persistent, entry);

	return -1;
}

int persistent_cache_write_entry(rdpPersistentCache* persistent, PERSISTENT_CACHE_ENTRY* entry)
{
	if (persistent->version == 3)
		return persistent_cache_write_entry_v3(persistent, entry);
	else if (persistent->version == 2)
		return persistent_cache_write_entry_v2(persistent, entry);

	return -1;
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

		fseek(persistent->fp, sizeof(PERSISTENT_CACHE_HEADER_V3), SEEK_SET);
	}
	else
	{
		status = persistent_cache_read_v2(persistent);

		fseek(persistent->fp, 0, SEEK_SET);
	}

	return status;
}

int persistent_cache_open_write(rdpPersistentCache* persistent)
{
	PERSISTENT_CACHE_HEADER_V3 header;

	persistent->fp = fopen(persistent->filename, "w+b");

	if (!persistent->fp)
		return -1;

	if (persistent->version == 3)
	{
		strncpy(header.sig, "RDP8bmp", 8);
		header.flags = 0x00000006;

		if (fwrite(&header, sizeof(PERSISTENT_CACHE_HEADER_V3), 1, persistent->fp) != 1)
			return -1;
	}

	ZeroMemory(persistent->bmpData, persistent->bmpSize);

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

	persistent->bmpSize = 0x4000;
	persistent->bmpData = (BYTE*) malloc(persistent->bmpSize);

	if (!persistent->bmpData)
		return NULL;

	return persistent;
}

void persistent_cache_free(rdpPersistentCache* persistent)
{
	if (!persistent)
		return;

	persistent_cache_close(persistent);

	free(persistent->filename);

	free(persistent->bmpData);

	free(persistent);
}