
Build OpenSSL for Windows:
https://github.com/wayk/PowerSSL

Install to C:\OpenSSL-Win32

cmake -G "Visual Studio 12" -T "v120_xp" -DCMAKE_PREFIX_PATH="C:\OpenSSL-Win32\static" -DMSVC_RUNTIME="static" .
