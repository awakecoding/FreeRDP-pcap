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

#ifndef FREERDP_PERSISTENT_CACHE_H
#define FREERDP_PERSISTENT_CACHE_H

#include <freerdp/api.h>
#include <freerdp/types.h>
#include <freerdp/update.h>
#include <freerdp/freerdp.h>

#include <winpr/crt.h>
#include <winpr/stream.h>

typedef struct rdp_persistent_cache rdpPersistentCache;

#include <freerdp/cache/cache.h>

struct rdp_persistent_cache
{
	FILE* fp;
	BOOL write;
	int version;
	int count;
	char* filename;
};

#ifdef __cplusplus
extern "C" {
#endif

FREERDP_API int persistent_cache_open(rdpPersistentCache* persistent, const char* filename, BOOL write, int version);
FREERDP_API int persistent_cache_close(rdpPersistentCache* persistent);

FREERDP_API rdpPersistentCache* persistent_cache_new();
FREERDP_API void persistent_cache_free(rdpPersistentCache* persistent);

#ifdef __cplusplus
}
#endif

#endif /* FREERDP_PERSISTENT_CACHE_H */
