#include <windows.h>
#include <winbase.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <sddl.h>

#define BUFFSIZE 2048
#define MAXEVENTMESSAGEFILECOUNT 32

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
BOOL GetDate(DWORD eventdate, char *buffer);
bool IsWindowsVistaOrHigher();
DWORD GetNewestEventRecordNumber(LPWSTR pwsComputerName, LPWSTR pwsPath, UINT64& dwNewest);
DWORD GetOldestEventRecordNumber(LPWSTR pwsComputerName, LPWSTR pwsPath, UINT64& dwOldest);
DWORD DumpEvents(LPWSTR pwsComputerName, LPWSTR pwsQuery);

static OSVERSIONINFO osvi;