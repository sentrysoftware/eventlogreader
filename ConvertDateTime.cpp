#include <windows.h>
#include <chrono>
#include <iomanip>
#include <sstream>

int FindTimeDiff(const std::wstring &dateStr, const std::wstring &timeStr, UINT64 &timediff)
{
	SYSTEMTIME stLocal, stUTC, stNow;
	FILETIME ftUTC, ftNow;
	ULARGE_INTEGER ui, uiNow;

	// Combine the date and time into one string for easier parsing
	std::wstring dateTimeStr = dateStr + L" " + timeStr;
	std::wstringstream wss(dateTimeStr);
	tm timeStruct = {};

	// Parse the date and time string into the tm structure
	wss >> std::get_time(&timeStruct, L"%Y-%m-%d %H:%M:%S");
	if (wss.fail())
	{
		return 1; // Failed to parse the date and time
	}

	// Convert parsed time to SYSTEMTIME
	stLocal.wYear = timeStruct.tm_year + 1900;
	stLocal.wMonth = timeStruct.tm_mon + 1;
	stLocal.wDay = timeStruct.tm_mday;
	stLocal.wHour = timeStruct.tm_hour;
	stLocal.wMinute = timeStruct.tm_min;
	stLocal.wSecond = timeStruct.tm_sec;
	stLocal.wMilliseconds = 0;

	// Convert to UTC time and FILETIME
	if (!TzSpecificLocalTimeToSystemTime(NULL, &stLocal, &stUTC))
		return 1;

	SystemTimeToFileTime(&stUTC, &ftUTC);
	ui.LowPart = ftUTC.dwLowDateTime;
	ui.HighPart = ftUTC.dwHighDateTime;

	// Get the current system time and convert to FILETIME
	GetSystemTime(&stNow);
	SystemTimeToFileTime(&stNow, &ftNow);
	uiNow.LowPart = ftNow.dwLowDateTime;
	uiNow.HighPart = ftNow.dwHighDateTime;

	// Calculate the time difference in milliseconds
	timediff = (uiNow.QuadPart - ui.QuadPart) / 10000; // Convert from 100-nanoseconds to milliseconds
	return 0;
}
