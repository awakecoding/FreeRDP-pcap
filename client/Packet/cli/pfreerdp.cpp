
#include "RdpDecoder.h"

static BOOL SaveBitmapToFile(HDC hDC, HBITMAP hBitmap, const char* filename)
{
	int iBits = 32;
	WORD wBitCount;
	BITMAP Bitmap;
	DWORD dwPaletteSize = 0;
	DWORD dwBmBitsSize = 0;
	DWORD dwDIBSize = 0;
	DWORD dwWritten = 0;
	BITMAPFILEHEADER bmfHdr;
	BITMAPINFOHEADER bi;
	LPBITMAPINFOHEADER lpbi;
	HANDLE fh, hDib;

	wBitCount = 24;

	GetObject(hBitmap, sizeof(Bitmap), (LPSTR) &Bitmap);
	bi.biSize = sizeof(BITMAPINFOHEADER);
	bi.biWidth = Bitmap.bmWidth;
	bi.biHeight = Bitmap.bmHeight;
	bi.biPlanes = 1;
	bi.biBitCount = wBitCount;
	bi.biCompression = BI_RGB;
	bi.biSizeImage = 0;
	bi.biXPelsPerMeter = 0;
	bi.biYPelsPerMeter = 0;
	bi.biClrImportant = 0;
	bi.biClrUsed = 0;
	dwBmBitsSize = ((Bitmap.bmWidth * wBitCount + 31) / 32) * 4 * Bitmap.bmHeight;

	hDib = GlobalAlloc(GHND, dwBmBitsSize + dwPaletteSize + sizeof(BITMAPINFOHEADER));
	lpbi = (LPBITMAPINFOHEADER) GlobalLock(hDib);
	*lpbi = bi;

	GetDIBits(hDC, hBitmap, 0, (UINT) Bitmap.bmHeight, (LPSTR) lpbi + sizeof(BITMAPINFOHEADER)
			+ dwPaletteSize, (BITMAPINFO *) lpbi, DIB_RGB_COLORS);

	fh = CreateFileA(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);

	if (fh == INVALID_HANDLE_VALUE)
		return FALSE;

	bmfHdr.bfType = 0x4D42;
	dwDIBSize = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + dwPaletteSize + dwBmBitsSize;
	bmfHdr.bfSize = dwDIBSize;
	bmfHdr.bfReserved1 = 0;
	bmfHdr.bfReserved2 = 0;
	bmfHdr.bfOffBits = (DWORD) sizeof(BITMAPFILEHEADER) + (DWORD) sizeof(BITMAPINFOHEADER) + dwPaletteSize;

	WriteFile(fh, (LPSTR) &bmfHdr, sizeof(BITMAPFILEHEADER), &dwWritten, NULL);
	WriteFile(fh, (LPSTR) lpbi, dwDIBSize, &dwWritten, NULL);

	GlobalUnlock(hDib);
	GlobalFree(hDib);
	CloseHandle(fh);

	return TRUE;
}

static HBITMAP CreateBitmapFromPixels(HDC hDC, UINT width, UINT height, BYTE* pBits)
{
	LONG bmpSize;
	UINT* pPixels = NULL;
	HBITMAP hBitmap = NULL;
	BITMAPINFO bmpInfo = { 0 };

	if (!width || !height)
		return NULL;
	
	bmpSize = width * height * 4;
	
	bmpInfo.bmiHeader.biWidth = width;
	bmpInfo.bmiHeader.biHeight = height * -1;
	bmpInfo.bmiHeader.biPlanes = 1;
	bmpInfo.bmiHeader.biBitCount = 32;
	bmpInfo.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);

	hBitmap = CreateDIBSection(hDC, (BITMAPINFO*) &bmpInfo, DIB_RGB_COLORS, (void**) &pPixels, NULL, 0);

	if (!hBitmap)
		return NULL;

	memcpy(pPixels, pBits, bmpSize);

	return hBitmap;
}

int SaveFrameToFile(BYTE* frameData, int frameWidth, int frameHeight, int frameIndex)
{
	HDC hDC;
	HBITMAP hBitmap;
	char filename[256];

	sprintf_s(filename, sizeof(filename) - 1, "rdp_%04d.bmp", frameIndex);

	hDC = GetDC(NULL);
	hBitmap = CreateBitmapFromPixels(hDC, frameWidth, frameHeight, frameData);
	SaveBitmapToFile(hDC, hBitmap, filename);
	DeleteObject(hBitmap);
	ReleaseDC(NULL, hDC);

	return 1;
}

int WINAPI PacketFrameCallback(void* frameParam,
	BYTE* frameData, int frameStep, int frameWidth, int frameHeight,
	int changeX, int changeY, int changeWidth, int changeHeight,
	UINT64 frameTime, int frameIndex)
{
	SaveFrameToFile(frameData, frameWidth, frameHeight, frameIndex);
	return 1;
}

int main(int argc, char** argv)
{
	RdpDecoder* dec;
	HANDLE finishEvent;

	dec = new RdpDecoder();
	finishEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	dec->setFinishEvent(finishEvent);
	dec->setFrameCallback(PacketFrameCallback, dec);

	if ((argc == 2) && (argv[1][0] != '/'))
	{
		/* use filename only */
		dec->open(argv[1]);
	}
	else
	{
		/* use FreeRDP arguments */
		dec->args(argc, argv);
		dec->open(NULL);
	}

	dec->start();

	WaitForSingleObject(finishEvent, INFINITE);

	dec->stop();
	dec->close();

	CloseHandle(finishEvent);
	delete dec;

	return 0;
}
