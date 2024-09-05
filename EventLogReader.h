#pragma once

#include <windows.h>
#include <string>

#define BUFFSIZE 2048
#define MAXEVENTMESSAGEFILECOUNT 32
#define MAX_NAME 256
#define ARRAY_SIZE 10

typedef struct _EventRecord
{
	DWORD recordnumber;
	char timegenerated[BUFFSIZE];
	char timewritten[BUFFSIZE];
	DWORD eventid;
	WORD eventtype;
	WORD eventcategory;
	DWORD reserved;
	WORD reservedflags;
	DWORD closingrecordnumber;
	BYTE sourcename[BUFFSIZE];
	BYTE computername[BUFFSIZE];
	wchar_t username[BUFFSIZE];
	wchar_t userdomain[BUFFSIZE];
	wchar_t description[BUFFSIZE];
	BYTE data[BUFFSIZE];
	DWORD datalength;
} EventRecord;


DWORD GetNewestEventRecordNumberPreW2K8(wchar_t *EventHostName, wchar_t *EventLogName);
DWORD GetDescription(wchar_t *EventLogName, wchar_t *sourcename, WORD sourcetype, DWORD id, wchar_t *description);
BOOL GetEventRecord(wchar_t *EventLogName, EVENTLOGRECORD *buffer, EventRecord *record, BOOL getusername, BOOL getdescription);
BOOL InitBaseDate(void);
DWORD GetNewestEventRecordNumber(LPWSTR pwsComputerName, LPWSTR pwsPath, UINT64& dwNewest);
DWORD GetOldestEventRecordNumber(LPWSTR pwsComputerName, LPWSTR pwsPath, UINT64& dwOldest);
DWORD DumpEvents(LPWSTR pwsComputerName, LPWSTR pwsQuery);
void PrintOSVersion();
EVT_HANDLE ConnectToRemoteHost(LPWSTR lpwsRemote, LPWSTR lpwsUsername, LPWSTR lpwsPassword);
DWORD ListEventChannels(EVT_HANDLE hRemote);
DWORD ListChannelProviders(EVT_HANDLE hRemote, LPWSTR pwsChannelName);
DWORD GetNewestEventRecordNumber(EVT_HANDLE hRemote, LPWSTR pwsPath, UINT64& dwNewest);
DWORD GetOldestEventRecordNumber(EVT_HANDLE hRemote, LPWSTR pwsPath, UINT64& dwOldest);
DWORD CountEvents(EVT_HANDLE hRemote, LPWSTR pwsQuery, UINT64& dwCount);
DWORD DumpEvents(EVT_HANDLE hRemote, LPWSTR pwsQuery, const char *printMethod);
int FindTimeDiff(const std::wstring &dateStr, const std::wstring &timeStr, UINT64 &timediff);
void SplitField(const wchar_t *field, const wchar_t delimiter, WCHAR *first, WCHAR *second);
DWORD GetEventRecordNumber(EVT_HANDLE hRemote, LPWSTR pwsPath, EVT_QUERY_FLAGS flDirection, UINT64& dwRecordNumber);
DWORD PrintEventDetails(EVT_HANDLE hRemote, EVT_HANDLE hEvent);
DWORD PrintEventReport(EVT_HANDLE hRemote, EVT_HANDLE hEvent);
DWORD PrintEventXML(EVT_HANDLE hRemote, EVT_HANDLE hEvent);
DWORD PrintEventList(EVT_HANDLE hEvent);
DWORD PrintError(LPWSTR lpszFunction);
LPWSTR GetMessageString(EVT_HANDLE hMetadata, EVT_HANDLE hEvent, EVT_FORMAT_MESSAGE_FLAGS FormatId);
LPWSTR ReplaceCarriageReturn(LPWSTR lpText);
EVT_HANDLE ConnectToRemote(LPWSTR lpwsRemote);
DWORD PrintResults(EVT_HANDLE hResults);
DWORD PrintEventData(EVT_HANDLE hEvent);
DWORD PrintEventSystemData(EVT_HANDLE hEvent);
DWORD PrintEventValues(EVT_HANDLE hEvent);
DWORD GetEventRecordID(EVT_HANDLE hEvent);

typedef LONG(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);