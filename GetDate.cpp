#include <string.h>
#include <stdio.h>
#include <windows.h>
#include <winnls.h>
#include <time.h>

BOOL GetDate(DWORD eventdate, char *buffer)
{
	char temptime[256];
	char tempdate[256];

	tm* time = _localtime32((__time32_t *)&eventdate);
	strftime(tempdate, sizeof(tempdate), "%Y-%m-%d", time);
	strftime(temptime, sizeof(temptime), "%H:%M:%S", time);

	strcpy(buffer, tempdate);
	strcat(buffer, " ");
	strcat(buffer, temptime);

	return 1;
}

bool IsWindowsVistaOrHigher() {
   OSVERSIONINFO osvi;
   ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
   osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
   GetVersionEx(&osvi);
   return osvi.dwMajorVersion >= 6;
}