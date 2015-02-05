#include <windows.h>
#include <sddl.h>
#include <stdio.h>
#include <winevt.h>
#include <time.h>

static const char version[] = "1.4.00";

#define BUFFSIZE 2048
#define MAX_NAME 256

EVT_HANDLE ConnectToRemoteHost(LPWSTR lpwsRemote, LPWSTR lpwsUsername, LPWSTR lpwsPassword);
DWORD ListEventChannels(EVT_HANDLE hRemote);
DWORD ListChannelProviders(EVT_HANDLE hRemote, LPWSTR pwsChannelName);
DWORD GetNewestEventRecordNumber(EVT_HANDLE hRemote, LPWSTR pwsPath, UINT64& dwNewest);
DWORD GetOldestEventRecordNumber(EVT_HANDLE hRemote, LPWSTR pwsPath, UINT64& dwOldest);
DWORD CountEvents(EVT_HANDLE hRemote, LPWSTR pwsQuery, UINT64& dwCount);
DWORD DumpEvents(EVT_HANDLE hRemote, LPWSTR pwsQuery, const char *printMethod);
int FindTimeDiff(const wchar_t *date, const wchar_t *time, UINT64& timediff);


void SplitField(const wchar_t *field, const wchar_t delimiter, WCHAR *first, WCHAR *second)
{
	// Split the first and second from field
	if(wcschr(field, delimiter))
	{
		int j = 0;
		while(field[j] != delimiter)
		{
			first[j] = field[j];
			j++;
		}
		first[j] = 0;
		j++;

		wcscpy(second, field+j);
	}
	else
	{
		first[0] = 0;
		wcscpy(second, field);
	}
}


///////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////
///////
///////    M A I N ( )
///////

int wmain(int argc, WCHAR *argv[])
{
	WCHAR hostname[MAX_NAME];
	WCHAR logpath[MAX_NAME];
	WCHAR name[MAX_NAME];
	WCHAR value[MAX_NAME];
	WCHAR user[MAX_NAME];
	WCHAR domain[MAX_NAME];
	WCHAR query[BUFFSIZE];
	WCHAR xmlQuery[BUFFSIZE];

	UINT64 oldestRecord;
	UINT64 newestRecord;
	UINT64 firstRecord = NULL;
	UINT64 lastRecord = NULL;
	UINT64 count;
	UINT64 timediff = 86400000; // 1 day

	HANDLE hEventLog = NULL;
	EVT_HANDLE host = NULL;

	DWORD status = ERROR_SUCCESS;
	DWORD dwSize = MAX_NAME;

	SID_NAME_USE sidType;
	PSID sid = NULL;

	LPWSTR lpSid = NULL;
	LPWSTR username = NULL;
	LPWSTR password = NULL;
	LPWSTR error = L"Invalid argument";
	
	int level;
	int whattodo;
	int pos = 0, upos = 0, ppos = 0;
	int i;

	for(i=1; i<argc; i++)
	{
		if(!_wcsicmp(argv[i], L"-help"))
			goto usage;

		if(!_wcsicmp(argv[i], L"-version"))
		{
			printf("%ws Version: %s\n", argv[0], version);

			// Find the OS version
			DWORD osv = GetVersion();
			DWORD major = (DWORD) (LOBYTE(LOWORD(osv)));
			DWORD minor = (DWORD) (HIBYTE(LOWORD(osv)));

			printf("Microsoft Windows Version: %d.%d\n", major, minor);
			return 0;
		}

		// Username
		if(!_wcsicmp(argv[i], L"-u"))
		{
			if(++i == argc)
				goto invalid_arg;
			username = argv[i];
			continue;
		}

		// Password
		if(!_wcsicmp(argv[i], L"-p"))
		{
			if(++i == argc)
				goto invalid_arg;
			password = argv[i];
			continue;
		}

		if(!_wcsicmp(argv[i], L"-ListEventLogs"))
		{
			pos = i;
			if(pos > 1)
				wcscpy(hostname, argv[1]);
			else
				hostname[0] = '\0';
			whattodo = 0;
			break;
		}

		if(!_wcsicmp(argv[i], L"-ListEventLogProviders"))
		{
			pos = i;
			whattodo = 1;
			break;
		}

		if(!_wcsicmp(argv[i], L"-GetNewestEventRecordNumber") || !_wcsicmp(argv[i], L"-newest"))
		{
			pos = i;
			whattodo = 2;
			break;
		}

		if(!_wcsicmp(argv[i], L"-GetOldestEventRecordNumber") || !_wcsicmp(argv[i], L"-oldest"))
		{
			pos = i;
			whattodo = 3;
			break;
		}

		if(!_wcsicmp(argv[i], L"-HowMany"))
		{
			pos = i;
			whattodo = 4;
			break;
		}

		if(!_wcsicmp(argv[i], L"-Dump"))
		{
			pos = i;
			whattodo = 5;
			break;
		}

		if(!_wcsicmp(argv[i], L"-CompleteDump"))
		{
			pos = i;
			whattodo = 6;
			break;
		}

		if(!_wcsicmp(argv[i], L"-XML"))
		{
			pos = i;
			whattodo = 7;
			break;
		}

		if(!_wcsicmp(argv[i], L"-Report"))
		{
			pos = i;
			whattodo = 8;
			break;
		}
	}

	if(pos == 0)
	{
		if(argc == 1)
			goto usage;

		goto invalid_arg;
	}
	
	// Split the host from the log
	if((pos > 1) && (whattodo > 0))
		SplitField(argv[1], L':', hostname, logpath);

	// Connect to the host
	host = ConnectToRemoteHost(hostname, username, password);

	switch(whattodo)
	{
		case 0: // ListEventLogs
			status = ListEventChannels(host);
			break;

		case 1: // ListEventLogProviders
			status = ListChannelProviders(host, logpath);
			break;

		case 2: // GetNewestEventRecordNumber
			if(ERROR_SUCCESS == (status = GetNewestEventRecordNumber(host, logpath, newestRecord)))
				wprintf(L"NewestEventRecordNumber=%u\n", newestRecord);
			break;

		case 3: // GetOldestEventRecordNumber
			if(ERROR_SUCCESS == (status = GetOldestEventRecordNumber(host, logpath, oldestRecord)))
				wprintf(L"OldestEventRecordNumber=%u\n", oldestRecord);
			break;

		case 4: // HowMany
		case 5: // Dump
		case 6: // CompleteDump
		case 7: // XML

			// Make sure we have at least 2 more args (first & last record nr)
			if(pos+2 >= argc)
				goto invalid_arg;

			// Determine the query start record number
			if(!_wcsicmp(argv[pos+1], L"oldest"))
				; // Nothing to do - from the oldest is the default
			else
			{
				if(!_wcsicmp(argv[pos+1], L"newest"))
				{
					if(ERROR_SUCCESS != (status = GetNewestEventRecordNumber(host, logpath, firstRecord)))
						goto cleanup;
				}
				else
				{
					firstRecord = _wtoi(argv[pos+1]);
					if(firstRecord == NULL)
					{
						error = L"Invalid query start record number";
						goto invalid_arg;
					}
				}

				// Add the query start record number
				swprintf(query, BUFFSIZE, L"%s EventRecordID &gt;= %d", query, (DWORD) firstRecord);
			}

			// Determine the query end record number
			if(!_wcsicmp(argv[pos+2], L"newest"))
				; // Nothing to do - till the newest is the default
			else
			{
				if(!_wcsicmp(argv[pos+2], L"oldest"))
				{
					if(ERROR_SUCCESS != (status = GetOldestEventRecordNumber(host, logpath, lastRecord)))
						goto cleanup;
				}
				else
				{
					lastRecord = _wtoi(argv[pos+2]);

					if(lastRecord == NULL)
					{
						error = L"Invalid query end record number";
						goto invalid_arg;
					}
				}

				// Add the query end record number
				if(firstRecord == NULL)
					swprintf(query, BUFFSIZE, L"%s EventRecordID &lt;= %d", query, (DWORD) lastRecord);
				else
				{
					if(firstRecord > lastRecord)
					{
						error = L"Invalid query start/end record numbers";
						goto invalid_arg;
					}
					swprintf(query, BUFFSIZE, L"%s and EventRecordID &lt;= %d", query, (DWORD) lastRecord);
				}
			}

			// Add any additional criteria
			for(i=pos+3; i<argc; i++)
			{
				if(!wcschr(argv[i], L'='))
				{
					error = L"Invalid syntax for criteria";
					goto invalid_arg;
				}

				// Read the name of the criteria
				SplitField(argv[i], L'=', name, value);

				if (!_wcsicmp(name, L"sourcename") || !_wcsicmp(name, L"providername"))
				{
					// Add Provider Name criteria
					if(*query == '\0') swprintf(query, BUFFSIZE, L"Provider[@Name='%s']", value);
					else swprintf(query, BUFFSIZE, L"%s and Provider[@Name='%s']", query, value);
				}

				else if (!_wcsicmp(name, L"category"))
				{
					// Add Task criteria
					if(*query == '\0') swprintf(query, BUFFSIZE, L"Task=%s", value);
					else swprintf(query, BUFFSIZE, L"%s and Task=%s", query, value);
				}

				else if (!_wcsicmp(name, L"id"))
				{
					// Add EventID criteria
					if(*query == '\0') swprintf(query, BUFFSIZE, L"EventID=%s", value);
					else swprintf(query, BUFFSIZE, L"%s and EventID=%s", query, value);
				}

				else if (!_wcsicmp(name, L"level"))
				{
					// Add Level criteria
					if (!_wcsicmp(value, L"critical")) level = 1;
					else if (!_wcsicmp(value, L"error")) level = 2;
					else if (!_wcsicmp(value, L"warning")) level = 3;
					else if (!_wcsicmp(value, L"information")) level = 4;
					else
					{
						error = L"Invalid event level";
						goto invalid_arg;
					}
					if(*query == '\0') swprintf(query, BUFFSIZE, L"Level=%d", level);
					else swprintf(query, BUFFSIZE, L"%s and Level=%d", query, level);
				}

				else if (!_wcsicmp(name, L"computer"))
				{
					// Add Computer criteria
					if(*query == '\0') swprintf(query, BUFFSIZE, L"Computer=\"%s\"", value);
					else swprintf(query, BUFFSIZE, L"%s and Computer=\"%s\"", query, value);
				}

				else if (!_wcsicmp(name, L"user"))
					wcscpy(user, value);   // Determine the user ID

				else if (!_wcsicmp(name, L"domain"))
					wcscpy(domain, value); // Determine the user domain

				else
				{
					error = L"Invalid criteria";
					goto invalid_arg;
				}
			}

			if ((*user != '\0') && 
				LookupAccountNameW(domain, user, &sid, &dwSize, domain, &dwSize, &sidType) && 
				ConvertSidToStringSidW(&sid, &lpSid))
			{
				// Add UserID criteria
				if(*query == '\0') swprintf(query, BUFFSIZE, L"Security[@UserID='%s']", lpSid);
				else swprintf(query, BUFFSIZE, L"%s and Security[@UserID='%s']", query, lpSid);
			}

			// Prepare the final query
			if(*query == '\0')
				swprintf(xmlQuery, BUFFSIZE, \
					L"<QueryList>" \
					L"  <Query Path=\"%s\">" \
					L"    <Select>*</Select>" \
					L"  </Query>" \
					L"</QueryList>", logpath);
			else
				swprintf(xmlQuery, BUFFSIZE, \
					L"<QueryList>" \
					L"  <Query Path=\"%s\">" \
					L"    <Select>Event/System[%s]</Select>" \
					L"  </Query>" \
					L"</QueryList>", logpath, query);

			if(whattodo == 4)
			{
				if(ERROR_SUCCESS == (status = CountEvents(host, xmlQuery, count)))
					wprintf(L"MatchingEventsNumber=%u\n", count);
			}

			else if(whattodo == 5)
				status = DumpEvents(host, xmlQuery, "list");

			else if(whattodo == 6)
				status = DumpEvents(host, xmlQuery, "detail");

			else if(whattodo == 7)
				status = DumpEvents(host, xmlQuery, "xml");

			break;

		case 8: // Report

			// Make sure we have at least 2 more args (date & time)
			if(pos+2 >= argc)
				goto invalid_arg;

			if (FindTimeDiff(argv[pos+1], argv[pos+2], timediff) == 1)
			{
				error = L"Invalid date/time format";
				goto invalid_arg;
			}

			swprintf(xmlQuery, BUFFSIZE, \
				L"<QueryList>" \
				L"  <Query Path=\"%s\">" \
				L"    <Select>Event/System[TimeCreated[timediff(@SystemTime) &lt;= %I64u]]</Select>" \
				L"  </Query>" \
				L"</QueryList>", logpath, timediff);

			status = DumpEvents(host, xmlQuery, "report");

			break;

		default:
			goto usage;
	}
	
	goto cleanup;

invalid_arg:
	wprintf(L"SW_ERROR: %ws\n", error);

usage:
	printf("\n%ws,  Version %s,  Displays Windows event log contents\n", argv[0], version);
	printf("\t\t\t\t\t on Microsoft Windows 2008 and above\n", argv[0], version);
	printf("Usage:\n");
	printf("  %ws -help\n", argv[0]);
	printf("  %ws -version\n", argv[0]);
	printf("  %ws [<host>] [-u <username> -p <password>] -ListEventLogs\n", argv[0]);
	printf("  %ws [<host>:]<log> [-u <username> -p <password>]\n", argv[0]);
	printf("\t\t\t -ListEventLogProviders\n");
	printf("\t\t\t -GetNewestEventRecordNumber\n");
	printf("\t\t\t -GetOldestEventRecordNumber\n");
	printf("\t\t\t -Report <date> <time>\n");
	printf("\t\t\t -Howmany <from> <to> [<criteria>]\n");
	printf("\t\t\t -Dump <from> <to> [<criteria>]\n");
	printf("\t\t\t -CompleteDump <from> <to> [<criteria>]\n\n");
	printf("Where: <host>     is optional remote host name\n");
	printf("       <username> is the optional login username for the remote host\n");
	printf("       <password> is the optional login password for the remote host\n");
	printf("       <log>      is the name of the event log: system|security|application\n");
	printf("       <date>     is the starting date to be searched from in YYYY-MM-DD format\n");
	printf("       <time>     is the starting time to be searched from in HH:MM:SS format\n");
	printf("       <from>     is the starting event record number or 'oldest'\n");
	printf("       <to>       is the ending event record number or 'newest'\n");
	printf("       <criteria> is optional criteria to be used for filtering the events\n");
	printf("                  supports: sourcename=<source name> category=<category>\n");
	printf("                  id=<event ID> level=<event level> computer=<computername>\n");
	printf("                  user=<username> domain=<domainname>\n\n");
	printf("Output:\n");
	printf("  -help          displays this usage information\n");
	printf("  -version       reports the version details of this executable\n");
	printf("  -ListEventLogs lists all registered event logs on the host\n");
	printf("  -ListEventLogProviders       lists all registered event providers for the log\n");
	printf("  -GetNewestEventRecordNumber  reports the newest event record number\n");
	printf("  -GetOldestEventRecordNumber  reports the oldes event record number\n");
	printf("  -Report        produces a pipe (|) delimited event report showing:\n");
	printf("                 RecordNumber, TimeGenerated, ComputerName, Provider,\n");
	printf("                 EventID, EventLevel & Message\n");
	printf("  -HowMany       reports number of matching events found\n");
	printf("  -Dump          produces a semicolon delimited report containing:\n");
	printf("                 RecordNumber, TimeGenerated, EventID, EventLevel,\n");
	printf("                 Provider, ComputerName, User, Domain & InsertionStrings\n");
	printf("  -CompleteDump  produces a semicolon delimited report containing:\n");
	printf("                 RecordNumber, TimeGenerated, EventID, EventLevel,\n");
	printf("                 Provider, ComputerName, User, Domain & Message\n\n");
	
	status = 1;

cleanup:
    if (hEventLog)
	    CloseEventLog(hEventLog);

	if(host)
        EvtClose(host);

    return status;
}

