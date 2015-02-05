#include <windows.h>
#include <sddl.h>
#include <stdio.h>
#include <winevt.h>

#pragma comment(lib, "wevtapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")

#define ARRAY_SIZE 10
#define MAX_NAME 256

DWORD GetEventRecordNumber(EVT_HANDLE hRemote, LPWSTR pwsPath, EVT_QUERY_FLAGS flDirection, UINT64& dwRecordNumber);
DWORD PrintEventDetails(EVT_HANDLE hRemote, EVT_HANDLE hEvent);
DWORD PrintEventReport(EVT_HANDLE hRemote, EVT_HANDLE hEvent);
DWORD PrintEventXML(EVT_HANDLE hRemote, EVT_HANDLE hEvent);
DWORD PrintEventList(EVT_HANDLE hEvent);
DWORD PrintError(LPWSTR lpszFunction);
LPWSTR GetMessageString(EVT_HANDLE hMetadata, EVT_HANDLE hEvent, EVT_FORMAT_MESSAGE_FLAGS FormatId);
LPWSTR ReplaceCarriageReturn(LPWSTR lpText);

// Create a session connect for the remote computer. Set the 
// Domain, User, and Password member to NULL to specify
// the current user.
EVT_HANDLE ConnectToRemoteHost(LPWSTR lpwsRemote, LPWSTR lpwsUsername, LPWSTR lpwsPassword)
{
    DWORD status = ERROR_SUCCESS;
	EVT_HANDLE hRemote = NULL;
    EVT_RPC_LOGIN Credentials;

	if(*lpwsRemote == '\0')
		return hRemote;

	RtlZeroMemory(&Credentials, sizeof(EVT_RPC_LOGIN));
	Credentials.Server = lpwsRemote;

	// Username & Password
	if(lpwsUsername == NULL)
	{
		Credentials.Domain = NULL;
		Credentials.User = NULL;
		Credentials.Password = NULL;
	}
	else
	{
		// Determine the domain/username
		WCHAR domain[MAX_NAME];
		WCHAR username[MAX_NAME];
		int i = 0;
		while(lpwsUsername[i] != '\\')
		{
			domain[i] = lpwsUsername[i];
			i++;
		}
		domain[i] = 0;
		i++;
		wcscpy(username, lpwsUsername+i);

		Credentials.Domain = domain;
		Credentials.User = username;
		Credentials.Password = lpwsPassword;
	}
	Credentials.Flags = EvtRpcLoginAuthNegotiate; 

	// This call creates a remote seesion context; it does not actually
	// create a connection to the remote computer. The connection to
	// the remote computer happens when you use the context.
	hRemote = EvtOpenSession(EvtRpcLogin, &Credentials, 0, 0);
	if(NULL == hRemote)
		PrintError(L"EvtOpenSession");

	SecureZeroMemory(&Credentials, sizeof(EVT_RPC_LOGIN));
    return hRemote;
}


DWORD ListEventChannels(EVT_HANDLE hRemote)
{
	EVT_HANDLE hChannels = NULL;
    LPWSTR pBuffer = NULL;
    LPWSTR pTemp = NULL;
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    DWORD status = ERROR_SUCCESS;

	// Get a handle to an enumerator that contains all the names of the 
    // channels registered on the computer.
    hChannels = EvtOpenChannelEnum(hRemote, 0);

    if (NULL == hChannels)
    {
		status = PrintError(L"EvtOpenChannelEnum");
        goto cleanup;
    }

    // Enumerate through the list of channel names. If the buffer is not big
    // enough reallocate the buffer. To get the configuration information for
    // a channel, call the EvtOpenChannelConfig function.
    while (true)
    {
        if (!EvtNextChannelPath(hChannels, dwBufferSize, pBuffer, &dwBufferUsed))
        {
            status = GetLastError();

            if (ERROR_NO_MORE_ITEMS == status)
                break;

			else if (ERROR_INSUFFICIENT_BUFFER == status)
            {
                dwBufferSize = dwBufferUsed;
                pTemp = (LPWSTR)realloc(pBuffer, dwBufferSize * sizeof(WCHAR));
                if (pTemp)
                {
                    pBuffer = pTemp;
                    pTemp = NULL;
                    EvtNextChannelPath(hChannels, dwBufferSize, pBuffer, &dwBufferUsed);
                }
                else
                {
					wprintf(L"SW_ERROR: realloc failed with %lu\n", status);
					status = ERROR_OUTOFMEMORY;
					goto cleanup;
                }
            }
            else
            {
				status = PrintError(L"EvtNextChannelPath");
				goto cleanup;
            }
        }
        wprintf(L"%s\n", pBuffer);
    }

cleanup:

    if (hChannels)
        EvtClose(hChannels);

    if (pBuffer)
        free(pBuffer);

	return status;
}

// Print the channel's configuration properties. Use the EVT_CHANNEL_CONFIG_PROPERTY_ID
// enumeration values to loop through all the properties.
DWORD ListChannelProviders(EVT_HANDLE hRemote, LPWSTR pwsChannelName)
{
    PEVT_VARIANT pProperty = NULL;  // Buffer that receives the property value
    PEVT_VARIANT pTemp = NULL;
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hChannel = NULL;

    hChannel = EvtOpenChannelConfig(hRemote, pwsChannelName, 0);

    if (NULL == hChannel) // Fails with 15007 (ERROR_EVT_CHANNEL_NOT_FOUND) if the channel is not found
    {
		status = PrintError(L"EvtOpenChannelConfig");
        goto cleanup;
    }

    // Get the specified property. If the buffer is too small, reallocate it.
    if(!EvtGetChannelConfigProperty(hChannel, EvtChannelPublisherList, 0, dwBufferSize, pProperty, &dwBufferUsed))
    {
        status = GetLastError();
        if(ERROR_INSUFFICIENT_BUFFER == status)
        {
            dwBufferSize = dwBufferUsed;
            pTemp = (PEVT_VARIANT)realloc(pProperty, dwBufferSize);
            if (pTemp)
            {
                pProperty = pTemp;
                pTemp = NULL;
                EvtGetChannelConfigProperty(hChannel, EvtChannelPublisherList, 0, dwBufferSize, pProperty, &dwBufferUsed);
            }
            else
            {
				wprintf(L"SW_ERROR: realloc failed with %lu\n", status);
				status = ERROR_OUTOFMEMORY;
                goto cleanup;
            }
        }

        if(ERROR_SUCCESS != (status = GetLastError()))
        {
			status = PrintError(L"EvtGetChannelConfigProperty");
            goto cleanup;
        }
    }

	for (DWORD i = 0; i < pProperty->Count; i++)
		wprintf(L"%s\n", pProperty->StringArr[i]);

cleanup:

    if (hChannel)
        EvtClose(hChannel);

    if (pProperty)
        free(pProperty);

    return status;
}



DWORD GetNewestEventRecordNumber(EVT_HANDLE hRemote, LPWSTR pwsPath, UINT64& dwNewest)
{
    return GetEventRecordNumber(hRemote, pwsPath, EvtQueryReverseDirection, dwNewest);
}

DWORD GetOldestEventRecordNumber(EVT_HANDLE hRemote, LPWSTR pwsPath, UINT64& dwOldest)
{
    return GetEventRecordNumber(hRemote, pwsPath, EvtQueryForwardDirection, dwOldest);
}

DWORD GetEventRecordNumber(EVT_HANDLE hRemote, LPWSTR pwsPath, EVT_QUERY_FLAGS flDirection, UINT64& dwRecordNumber)
{
	DWORD status = ERROR_SUCCESS;
	DWORD dwReturned = 0;
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    DWORD dwPropertyCount = 0;
    EVT_HANDLE hResults = NULL;
    EVT_HANDLE hEvents[ARRAY_SIZE];
	EVT_HANDLE hContext = NULL;
	PEVT_VARIANT pRenderedValues = NULL;

    // Query in forward direction, so the oldest is on the top
	hResults = EvtQuery(hRemote, pwsPath, L"*", EvtQueryChannelPath | flDirection);
    if(NULL == hResults)
    {
		status = PrintError(L"EvtQuery");
		goto cleanup;
    }

    // Get the first event from the result set
    if(!EvtNext(hResults, 1, hEvents, INFINITE, 0, &dwReturned))
    {
        status = PrintError(L"EvtNext");
        goto cleanup;
    }

    // Identify the components of the event that you want to render. In this case,
    // render the system section of the event.
    hContext = EvtCreateRenderContext(0, NULL, EvtRenderContextSystem);
    if(NULL == hContext)
    {
		status = PrintError(L"EvtCreateRenderContext");
        goto cleanup;
    }

    // When you render the user data or system section of the event, you must specify
    // the EvtRenderEventValues flag. The function returns an array of variant values 
    // for each element in the user data or system section of the event. For user data
    // or event data, the values are returned in the same order as the elements are 
    // defined in the event. For system data, the values are returned in the order defined
    // in the EVT_SYSTEM_PROPERTY_ID enumeration.
    if(!EvtRender(hContext, hEvents[0], EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount))
    {
        if(ERROR_INSUFFICIENT_BUFFER == (status = GetLastError()))
        {
            dwBufferSize = dwBufferUsed;
            pRenderedValues = (PEVT_VARIANT)malloc(dwBufferSize);
            if(pRenderedValues)
            {
                EvtRender(hContext, hEvents[0], EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount);
            }
            else
            {
				wprintf(L"SW_ERROR: malloc failed with %lu\n", status);
                status = ERROR_OUTOFMEMORY;
                goto cleanup;
            }
        }

        if(ERROR_SUCCESS != (status = GetLastError()))
        {
			status = PrintError(L"EvtRender");
            goto cleanup;
        }
    }

    // Event Record ID
	dwRecordNumber = pRenderedValues[EvtSystemEventRecordId].UInt64Val;

cleanup:

    if(hEvents[0])
		EvtClose(hEvents[0]);

	if(hResults)
        EvtClose(hResults);

	if(hContext)
        EvtClose(hContext);

	if(pRenderedValues)
        free(pRenderedValues);

	return status;
}

DWORD CountEvents(EVT_HANDLE hRemote, LPWSTR pwsQuery, UINT64& dwCount)
{
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hResults = NULL;
	DWORD dwReturned = 0;
	EVT_HANDLE hEvents[ARRAY_SIZE];
	DWORD dwRecord = NULL;
	//wprintf(L"pwsQuery <%ws>\n", pwsQuery);

	// Query the host
    hResults = EvtQuery(hRemote, NULL, pwsQuery, EvtQueryChannelPath | EvtQueryForwardDirection);
    if(NULL == hResults)
    {
        status = PrintError(L"EvtQuery");
		goto cleanup;
    }
	
    dwCount = 0;
	while(true)
    {
        // Get a block of events from the result set
        if(!EvtNext(hResults, ARRAY_SIZE, hEvents, INFINITE, 0, &dwReturned))
        {
			if(ERROR_NO_MORE_ITEMS != (status = GetLastError()))
				status = PrintError(L"EvtNext");
			else
				status = ERROR_SUCCESS;

			goto cleanup;
        }
		dwCount = dwCount + dwReturned;
    }

cleanup:

    for(DWORD i = 0; i < dwReturned; i++)
        if(NULL != hEvents[i])
            EvtClose(hEvents[i]);

	if(hResults)
        EvtClose(hResults);

	return status;
}

DWORD DumpEvents(EVT_HANDLE hRemote, LPWSTR pwsQuery, const char *printMethod)
{
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hResults = NULL;
	DWORD dwReturned = 0;
	EVT_HANDLE hEvents[ARRAY_SIZE];
	DWORD dwRecord = NULL;
	//wprintf(L"pwsQuery <%ws>\n", pwsQuery);

	// Query the host
    hResults = EvtQuery(hRemote, NULL, pwsQuery, EvtQueryChannelPath | EvtQueryForwardDirection);
    if(NULL == hResults)
    {
        status = PrintError(L"EvtQuery");
		goto cleanup;
    }
	
    while(true)
    {
        // Get a block of events from the result set
        if(!EvtNext(hResults, ARRAY_SIZE, hEvents, INFINITE, 0, &dwReturned))
        {
			if(ERROR_NO_MORE_ITEMS != (status = GetLastError()))
				status = PrintError(L"EvtNext");

			goto cleanup;
        }

        // For each event, render and print the event details
		if(printMethod == "list")
		{
			for(DWORD i = 0; i < dwReturned; i++)
			{
				if(ERROR_SUCCESS == (status = PrintEventList(hEvents[i])))
				{
					EvtClose(hEvents[i]);
					hEvents[i] = NULL;
				}
				else
					goto cleanup;
			}
		}
		else if(printMethod == "xml")
		{
			for(DWORD i = 0; i < dwReturned; i++)
			{
				if(ERROR_SUCCESS == (status = PrintEventXML(hRemote, hEvents[i])))
				{
					EvtClose(hEvents[i]);
					hEvents[i] = NULL;
				}
				else
					goto cleanup;
			}
		}
		else if(printMethod == "detail")
		{
			for(DWORD i = 0; i < dwReturned; i++)
			{
				if(ERROR_SUCCESS == (status = PrintEventDetails(hRemote, hEvents[i])))
				{
					EvtClose(hEvents[i]);
					hEvents[i] = NULL;
				}
				else
					goto cleanup;
			}
		}
		else if(printMethod == "report")
		{
			for (DWORD i = 0; i < dwReturned; i++)
			{
				if(ERROR_SUCCESS == (status = PrintEventReport(hRemote, hEvents[i])))
				{
					EvtClose(hEvents[i]);
					hEvents[i] = NULL;
				}
				else
					goto cleanup;
			}
		}
		else goto cleanup;
    }

cleanup:

	for(DWORD i = 0; i < dwReturned; i++)
        if(NULL != hEvents[i])
            EvtClose(hEvents[i]);

	if(hResults)
	{
		EvtClose(hResults);
		hResults = NULL;
	}
	return status;
}

DWORD PrintEventDetails(EVT_HANDLE hRemote, EVT_HANDLE hEvent)
{
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hContext = NULL;
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    DWORD dwPropertyCount = 0;
	PEVT_VARIANT pRenderedValues = NULL;
    LPOLESTR  pwsSid = NULL;
    ULONGLONG ullTimeStamp = 0;
    SYSTEMTIME stUTC, stLocal;
    FILETIME ft;
	DWORD dwSize = MAX_NAME;
	WCHAR lpName[MAX_NAME];
    WCHAR lpDomain[MAX_NAME];
	SID_NAME_USE SidType;
	EVT_HANDLE hProviderMetadata = NULL;
	LPWSTR pwsMessage = NULL;

    // Identify the components of the event that you want to render. In this case,
    // render the system section of the event.
    hContext = EvtCreateRenderContext(0, NULL, EvtRenderContextSystem);
    if(NULL == hContext)
    {
        status = PrintError(L"EvtCreateRenderContext");
        goto cleanup;
    }

    // When you render the user data or system section of the event, you must specify
    // the EvtRenderEventValues flag. The function returns an array of variant values 
    // for each element in the user data or system section of the event. For user data
    // or event data, the values are returned in the same order as the elements are 
    // defined in the event. For system data, the values are returned in the order defined
    // in the EVT_SYSTEM_PROPERTY_ID enumeration.
    if(!EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount))
    {
        if(ERROR_INSUFFICIENT_BUFFER == (status = GetLastError()))
        {
            dwBufferSize = dwBufferUsed;
            pRenderedValues = (PEVT_VARIANT)malloc(dwBufferSize);
            if(pRenderedValues)
                EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount);
            else
            {
				wprintf(L"SW_ERROR: malloc failed for EvtRender with %lu\n", GetLastError());
                status = ERROR_OUTOFMEMORY;
                goto cleanup;
            }
        }

        if(ERROR_SUCCESS != (status = GetLastError()))
        {
            status = PrintError(L"EvtRender");
            goto cleanup;
        }
    }

    // Event Record ID
	wprintf(L"%I64u;", pRenderedValues[EvtSystemEventRecordId].UInt64Val);

    // Time Created - convert to local time
	ullTimeStamp = pRenderedValues[EvtSystemTimeCreated].FileTimeVal;
    ft.dwHighDateTime = (DWORD)((ullTimeStamp >> 32) & 0xFFFFFFFF);
    ft.dwLowDateTime = (DWORD)(ullTimeStamp & 0xFFFFFFFF);
    FileTimeToSystemTime(&ft, &stUTC);
    SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);
    wprintf(L"%02d-%02d-%02d %02d:%02d:%02d;", 
        stLocal.wYear, stLocal.wMonth, stLocal.wDay, stLocal.wHour, stLocal.wMinute, stLocal.wSecond);

    // Event ID
	DWORD EventID = pRenderedValues[EvtSystemEventID].UInt16Val;
    wprintf(L"%lu;", EventID);

	// Level
    wprintf(L"%u;", (EvtVarTypeNull == pRenderedValues[EvtSystemLevel].Type) ? 0 : pRenderedValues[EvtSystemLevel].ByteVal);

    // Provider Name
	LPCWSTR pwsProviderName =pRenderedValues[EvtSystemProviderName].StringVal;
	wprintf(L"%s;", pwsProviderName);

    // Computer
	wprintf(L"%s;", pRenderedValues[EvtSystemComputer].StringVal);

    // Username & Domain
	if(EvtVarTypeNull != pRenderedValues[EvtSystemUserID].Type)
    {
		if( !LookupAccountSidW(NULL, pRenderedValues[EvtSystemUserID].SidVal,
                              lpName, &dwSize, lpDomain, 
                              &dwSize, &SidType)) 
		{
			wcscpy(lpName, L"N/A");
			wcscpy(lpDomain, L"N/A");
		}
    }
	else
	{
		wcscpy(lpName, L"N/A");
		wcscpy(lpDomain, L"N/A");
	}
	wprintf(L"%s;", lpName);
	wprintf(L"%s;", lpDomain);


    // Get the handle to the provider's metadata that contains the message strings.
    hProviderMetadata = EvtOpenPublisherMetadata(hRemote, pwsProviderName, NULL, 0, 0);
    if(NULL == hProviderMetadata)
    {
        status = PrintError(L"EvtOpenPublisherMetadata");
        goto cleanup;
    }

    // Description
    pwsMessage = GetMessageString(hProviderMetadata, hEvent, EvtFormatMessageEvent);
    if(pwsMessage)
    {
		wprintf(L"%s\n", ReplaceCarriageReturn(pwsMessage));
        free(pwsMessage);
        pwsMessage = NULL;
    }

cleanup:

	if(hContext)
	{
        EvtClose(hContext);
		hContext = NULL;
	}

    if(pRenderedValues)
	{
        free(pRenderedValues);
		pRenderedValues = NULL;
	}

    if(hProviderMetadata)
	{
        EvtClose(hProviderMetadata);
		hProviderMetadata = NULL;
	}

    return status;
}

DWORD PrintEventReport(EVT_HANDLE hRemote, EVT_HANDLE hEvent)
{
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hContext = NULL;
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    DWORD dwPropertyCount = 0;
	PEVT_VARIANT pRenderedValues = NULL;
    LPOLESTR  pwsSid = NULL;
    ULONGLONG ullTimeStamp = 0;
    SYSTEMTIME stUTC, stLocal;
    FILETIME ft;
	DWORD dwSize = MAX_NAME;
	EVT_HANDLE hProviderMetadata = NULL;
	LPWSTR pwsMessage = NULL;

    // Identify the components of the event that you want to render. In this case,
    // render the system section of the event.
    hContext = EvtCreateRenderContext(0, NULL, EvtRenderContextSystem);
    if(NULL == hContext)
    {
        status = PrintError(L"EvtCreateRenderContext");
        goto cleanup;
    }

    // When you render the user data or system section of the event, you must specify
    // the EvtRenderEventValues flag. The function returns an array of variant values 
    // for each element in the user data or system section of the event. For user data
    // or event data, the values are returned in the same order as the elements are 
    // defined in the event. For system data, the values are returned in the order defined
    // in the EVT_SYSTEM_PROPERTY_ID enumeration.
    if(!EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount))
    {
        if(ERROR_INSUFFICIENT_BUFFER == (status = GetLastError()))
        {
            dwBufferSize = dwBufferUsed;
            pRenderedValues = (PEVT_VARIANT)malloc(dwBufferSize);
            if(pRenderedValues)
                EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount);
            else
            {
				wprintf(L"SW_ERROR: malloc failed for EvtRender with %lu\n", GetLastError());
                status = ERROR_OUTOFMEMORY;
                goto cleanup;
            }
        }

        if(ERROR_SUCCESS != (status = GetLastError()))
        {
            status = PrintError(L"EvtRender");
            goto cleanup;
        }
    }

	// Event Record ID
	wprintf(L"%I64u | ", pRenderedValues[EvtSystemEventRecordId].UInt64Val);

    // Time Created - convert to local time
	ullTimeStamp = pRenderedValues[EvtSystemTimeCreated].FileTimeVal;
    ft.dwHighDateTime = (DWORD)((ullTimeStamp >> 32) & 0xFFFFFFFF);
    ft.dwLowDateTime = (DWORD)(ullTimeStamp & 0xFFFFFFFF);
    FileTimeToSystemTime(&ft, &stUTC);
    SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);
    wprintf(L"%02d-%02d-%02d %02d:%02d:%02d | ", 
        stLocal.wYear, stLocal.wMonth, stLocal.wDay, stLocal.wHour, stLocal.wMinute, stLocal.wSecond);
	
    // Computer
	if(wcslen(pRenderedValues[EvtSystemComputer].StringVal) > 20)
		wprintf(L"%.18s.. | ", pRenderedValues[EvtSystemComputer].StringVal);
	else
		wprintf(L"%-20s | ", pRenderedValues[EvtSystemComputer].StringVal);
	
    // Provider Name
	LPCWSTR pwsProviderName =pRenderedValues[EvtSystemProviderName].StringVal;
	if(wcslen(pwsProviderName) > 40)
		wprintf(L"%.38s.. | ", pwsProviderName);
	else
		wprintf(L"%-40s | ", pwsProviderName);
	
	// Event ID
	DWORD EventID = pRenderedValues[EvtSystemEventID].UInt16Val;
    wprintf(L"%4lu | ", EventID);
	
    // Get the handle to the provider's metadata that contains the message strings.
    hProviderMetadata = EvtOpenPublisherMetadata(hRemote, pwsProviderName, NULL, 0, 0);
    if(NULL == hProviderMetadata)
    {
        status = PrintError(L"EvtOpenPublisherMetadata");
        goto cleanup;
    }
	
	// Level
	pwsMessage = GetMessageString(hProviderMetadata, hEvent, EvtFormatMessageLevel);
    if(pwsMessage)
    {
    	wprintf(L"%-11s | ", CharUpperW(pwsMessage));
    	free(pwsMessage);
		pwsMessage = NULL;
    }
	
    // Message
    pwsMessage = GetMessageString(hProviderMetadata, hEvent, EvtFormatMessageEvent);
    if(pwsMessage)
    {
		wprintf(L"%s\n", ReplaceCarriageReturn(pwsMessage));
		free(pwsMessage);
        pwsMessage = NULL;
    }
	
cleanup:

	if(hContext)
	{
		EvtClose(hContext);
		hContext = NULL;
	}

	if(pRenderedValues)
	{
        free(pRenderedValues);
		pRenderedValues = NULL;
	}

	if(hProviderMetadata)
	{
        EvtClose(hProviderMetadata);
		hProviderMetadata = NULL;
	}

	return status;
}

DWORD PrintEventXML(EVT_HANDLE hRemote, EVT_HANDLE hEvent)
{
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hContext = NULL;
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    DWORD dwPropertyCount = 0;
	PEVT_VARIANT pRenderedValues = NULL;
    LPOLESTR  pwsSid = NULL;
    ULONGLONG ullTimeStamp = 0;
	DWORD dwSize = MAX_NAME;
	EVT_HANDLE hProviderMetadata = NULL;
	LPWSTR pwsMessage = NULL;

    // Identify the components of the event that you want to render. In this case,
    // render the system section of the event.
    hContext = EvtCreateRenderContext(0, NULL, EvtRenderContextSystem);
    if(NULL == hContext)
    {
        status = PrintError(L"EvtCreateRenderContext");
        goto cleanup;
    }

    // When you render the user data or system section of the event, you must specify
    // the EvtRenderEventValues flag. The function returns an array of variant values 
    // for each element in the user data or system section of the event. For user data
    // or event data, the values are returned in the same order as the elements are 
    // defined in the event. For system data, the values are returned in the order defined
    // in the EVT_SYSTEM_PROPERTY_ID enumeration.
    if(!EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount))
    {
        if(ERROR_INSUFFICIENT_BUFFER == (status = GetLastError()))
        {
            dwBufferSize = dwBufferUsed;
            pRenderedValues = (PEVT_VARIANT)malloc(dwBufferSize);
            if(pRenderedValues)
                EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount);
            else
            {
				wprintf(L"SW_ERROR: malloc failed for EvtRender with %lu\n", GetLastError());
                status = ERROR_OUTOFMEMORY;
                goto cleanup;
            }
        }

        if(ERROR_SUCCESS != (status = GetLastError()))
        {
            status = PrintError(L"EvtRender");
            goto cleanup;
        }
    }

    // Provider Name
	LPCWSTR pwsProviderName =pRenderedValues[EvtSystemProviderName].StringVal;

    // Get the handle to the provider's metadata that contains the message strings.
    hProviderMetadata = EvtOpenPublisherMetadata(hRemote, pwsProviderName, NULL, 0, 0);
    if(NULL == hProviderMetadata)
    {
        status = PrintError(L"EvtOpenPublisherMetadata");
        goto cleanup;
    }

	pwsMessage = GetMessageString(hProviderMetadata, hEvent, EvtFormatMessageXml);
    if(pwsMessage)
    {
        wprintf(L"%s\n\n", pwsMessage);
        free(pwsMessage);
        pwsMessage = NULL;
    }

cleanup:

	if(hContext)
	{
        EvtClose(hContext);
		hContext = NULL;
	}

    if(pRenderedValues)
	{
        free(pRenderedValues);
		pRenderedValues = NULL;
	}

    if(hProviderMetadata)
	{
        EvtClose(hProviderMetadata);
		hProviderMetadata = NULL;
	}

    return status;
}

DWORD PrintEventList(EVT_HANDLE hEvent)
{
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hContext = NULL;
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    DWORD dwPropertyCount = 0;
	PEVT_VARIANT pRenderedValues = NULL;
    LPOLESTR  pwsSid = NULL;
    ULONGLONG ullTimeStamp = 0;
    SYSTEMTIME stUTC, stLocal;
    FILETIME ft;
	DWORD dwSize = MAX_NAME;
	WCHAR lpName[MAX_NAME];
    WCHAR lpDomain[MAX_NAME];
	SID_NAME_USE SidType;

    // Identify the components of the event that you want to render. In this case,
    // render the system section of the event.
    hContext = EvtCreateRenderContext(0, NULL, EvtRenderContextSystem);
    if(NULL == hContext)
    {
        status = PrintError(L"EvtCreateRenderContext");
        goto cleanup;
    }

    // When you render the user data or system section of the event, you must specify
    // the EvtRenderEventValues flag. The function returns an array of variant values 
    // for each element in the user data or system section of the event. For user data
    // or event data, the values are returned in the same order as the elements are 
    // defined in the event. For system data, the values are returned in the order defined
    // in the EVT_SYSTEM_PROPERTY_ID enumeration.
    if(!EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount))
    {
        if(ERROR_INSUFFICIENT_BUFFER == (status = GetLastError()))
        {
            dwBufferSize = dwBufferUsed;
            pRenderedValues = (PEVT_VARIANT)malloc(dwBufferSize);
            if(pRenderedValues)
                EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount);
            else
            {
				wprintf(L"SW_ERROR: malloc failed for EvtRender with %lu\n", GetLastError());
                status = ERROR_OUTOFMEMORY;
                goto cleanup;
            }
        }

        if(ERROR_SUCCESS != (status = GetLastError()))
        {
            status = PrintError(L"EvtRender");
            goto cleanup;
        }
    }

    // Event Record ID
	wprintf(L"%I64u;", pRenderedValues[EvtSystemEventRecordId].UInt64Val);

    // Time Created - convert to local time
	ullTimeStamp = pRenderedValues[EvtSystemTimeCreated].FileTimeVal;
    ft.dwHighDateTime = (DWORD)((ullTimeStamp >> 32) & 0xFFFFFFFF);
    ft.dwLowDateTime = (DWORD)(ullTimeStamp & 0xFFFFFFFF);
    FileTimeToSystemTime(&ft, &stUTC);
    SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);
    wprintf(L"%02d-%02d-%02d %02d:%02d:%02d;", 
        stLocal.wYear, stLocal.wMonth, stLocal.wDay, stLocal.wHour, stLocal.wMinute, stLocal.wSecond);

    // Event ID
	DWORD EventID = pRenderedValues[EvtSystemEventID].UInt16Val;
    wprintf(L"%lu;", EventID);

	// Level
    wprintf(L"%u;", (EvtVarTypeNull == pRenderedValues[EvtSystemLevel].Type) ? 0 : pRenderedValues[EvtSystemLevel].ByteVal);

    // Provider Name
	LPCWSTR pwsProviderName =pRenderedValues[EvtSystemProviderName].StringVal;
	wprintf(L"%s;", pwsProviderName);

    // Computer
	wprintf(L"%s;", pRenderedValues[EvtSystemComputer].StringVal);

    // Username & Domain
	if(EvtVarTypeNull != pRenderedValues[EvtSystemUserID].Type)
    {
		if( !LookupAccountSidW(NULL, pRenderedValues[EvtSystemUserID].SidVal,
                              lpName, &dwSize, lpDomain, 
                              &dwSize, &SidType)) 
		{
			wcscpy(lpName, L"N/A");
			wcscpy(lpDomain, L"N/A");
		}
    }
	else
	{
		wcscpy(lpName, L"N/A");
		wcscpy(lpDomain, L"N/A");
	}
	wprintf(L"%s;%s;N/A;N/A;\n", lpName, lpDomain); // N/A for insertion strings at the mo!!

cleanup:

	if(hContext)
	{
        EvtClose(hContext);
		hContext = NULL;
	}

    if(pRenderedValues)
	{
        free(pRenderedValues);
		pRenderedValues = NULL;
	}

    return status;
}

// Gets the specified message string from the event. If the event does not
// contain the specified message, the function returns NULL.
LPWSTR GetMessageString(EVT_HANDLE hMetadata, EVT_HANDLE hEvent, EVT_FORMAT_MESSAGE_FLAGS FormatId)
{
    LPWSTR pBuffer = NULL;
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    DWORD status = 0;

    if(!EvtFormatMessage(hMetadata, hEvent, 0, 0, NULL, FormatId, dwBufferSize, pBuffer, &dwBufferUsed))
    {
        status = GetLastError();
        if(ERROR_INSUFFICIENT_BUFFER == status)
        {
            // An event can contain one or more keywords. The function returns keywords
            // as a list of keyword strings. To process the list, you need to know the
            // size of the buffer, so you know when you have read the last string, or you
            // can terminate the list of strings with a second null terminator character 
            // as this example does.
            if((EvtFormatMessageKeyword == FormatId))
                pBuffer[dwBufferSize-1] = L'\0';
            else
                dwBufferSize = dwBufferUsed;

            pBuffer = (LPWSTR)malloc(dwBufferSize * sizeof(WCHAR));

            if(pBuffer)
            {
                EvtFormatMessage(hMetadata, hEvent, 0, 0, NULL, FormatId, dwBufferSize, pBuffer, &dwBufferUsed);

                // Add the second null terminator character.
                if((EvtFormatMessageKeyword == FormatId))
                    pBuffer[dwBufferUsed-1] = L'\0';
            }
            else
				wprintf(L"SW_ERROR: malloc failed for EvtFormatMessage\n");
        }
        else if(ERROR_EVT_MESSAGE_NOT_FOUND == status || ERROR_EVT_MESSAGE_ID_NOT_FOUND == status)
            ;
        else
			PrintError(L"EvtFormatMessage");
    }

    return pBuffer;
}


DWORD PrintError(LPWSTR lpszFunction) 
{ 
    // Retrieve the system error message for the last-error code
    LPVOID lpMsgBuf;
    DWORD dw = GetLastError(); 

    FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | 
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR) &lpMsgBuf,
        0, NULL );

    // Print the error message and exit the process
	wprintf(L"SW_ERROR: %ws failed with error %d: %ws\n", lpszFunction, dw, lpMsgBuf);

    LocalFree(lpMsgBuf);
	return dw;
}


LPWSTR ReplaceCarriageReturn(LPWSTR lpText)
{
	LPWSTR pBuffer = NULL;
	int i, j, textLen;

	if(wcschr(lpText, L'\n'))
	{
		textLen = wcslen(lpText);
		pBuffer = (LPWSTR)malloc(textLen * sizeof(WCHAR));

        if(!pBuffer)
		{
			wprintf(L"SW_ERROR: malloc failed for ReplaceCarriageReturn\n");
			return L"";
		}

		j = 0;
		for(i = 0; i < textLen; i++)
		{
			if(lpText[i] == L'\n')
			{
				pBuffer[j] = L' ';
				j++;
			}
			else if(lpText[i] == L'\r')
				;
			else
			{
				pBuffer[j] = lpText[i];
				j++;
			}
		}
		pBuffer[j] = L'\0';
		return pBuffer;
	}
	else
		return lpText;
}








EVT_HANDLE ConnectToRemote(LPWSTR lpwsRemote);
DWORD PrintResults(EVT_HANDLE hResults);
DWORD PrintEventData(EVT_HANDLE hEvent);
DWORD PrintEventSystemData(EVT_HANDLE hEvent);
DWORD PrintEventValues(EVT_HANDLE hEvent);
DWORD GetEventRecordID(EVT_HANDLE hEvent);


EVT_HANDLE ConnectToRemote(LPWSTR lpwsRemote)
{
    DWORD status = ERROR_SUCCESS;
	EVT_HANDLE hRemote = NULL;
    EVT_RPC_LOGIN Credentials;

	RtlZeroMemory(&Credentials, sizeof(EVT_RPC_LOGIN));
	Credentials.Server = lpwsRemote;
	Credentials.Domain = NULL;
	Credentials.User = NULL;
	Credentials.Password = NULL;
	Credentials.Flags = EvtRpcLoginAuthNegotiate; 

	// This call creates a remote seesion context; it does not actually
	// create a connection to the remote computer. The connection to
	// the remote computer happens when you use the context.
	hRemote = EvtOpenSession(EvtRpcLogin, &Credentials, 0, 0);
	if(NULL == hRemote)
		PrintError(L"EvtOpenSession");

	SecureZeroMemory(&Credentials, sizeof(EVT_RPC_LOGIN));

    return hRemote;
}

// Enumerate all the events in the result set. 
DWORD PrintResults(EVT_HANDLE hResults)
{
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hEvents[ARRAY_SIZE];
    DWORD dwReturned = 0;

    while(true)
    {
        // Get a block of events from the result set.
        if(!EvtNext(hResults, ARRAY_SIZE, hEvents, INFINITE, 0, &dwReturned))
        {
            if(ERROR_NO_MORE_ITEMS != (status = GetLastError()))
            {
                wprintf(L"EvtNext failed with %lu\n", status);
            }

            goto cleanup;
        }

        // For each event, call the Print Event function which renders the
        // event for display. Print Event is shown in RenderingEvents.
        for(DWORD i = 0; i < dwReturned; i++)
        {
            if(ERROR_SUCCESS == (status = PrintEventSystemData(hEvents[i])))
            {
                EvtClose(hEvents[i]);
                hEvents[i] = NULL;
            }
            else
            {
                goto cleanup;
            }
        }
    }

cleanup:

    for(DWORD i = 0; i < dwReturned; i++)
    {
        if(NULL != hEvents[i])
            EvtClose(hEvents[i]);
    }

    return status;
}



DWORD SummarizeEvent(EVT_HANDLE hRemote, EVT_HANDLE hEvent)
{
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hContext = NULL;
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    DWORD dwPropertyCount = 0;
	PEVT_VARIANT pRenderedValues = NULL;
    LPOLESTR  pwsSid = NULL;
    ULONGLONG ullTimeStamp = 0;
    SYSTEMTIME stUTC, stLocal;
    FILETIME ft;
	DWORD dwSize = MAX_NAME;
	WCHAR lpName[MAX_NAME];
    WCHAR lpDomain[MAX_NAME];
	SID_NAME_USE SidType;
	EVT_HANDLE hProviderMetadata = NULL;
	LPWSTR pwsMessage = NULL;

    // Identify the components of the event that you want to render. In this case,
    // render the system section of the event.
    hContext = EvtCreateRenderContext(0, NULL, EvtRenderContextSystem);
    if(NULL == hContext)
    {
        status = PrintError(L"EvtCreateRenderContext");
        goto cleanup;
    }

    // When you render the user data or system section of the event, you must specify
    // the EvtRenderEventValues flag. The function returns an array of variant values 
    // for each element in the user data or system section of the event. For user data
    // or event data, the values are returned in the same order as the elements are 
    // defined in the event. For system data, the values are returned in the order defined
    // in the EVT_SYSTEM_PROPERTY_ID enumeration.
    if(!EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount))
    {
        if(ERROR_INSUFFICIENT_BUFFER == (status = GetLastError()))
        {
            dwBufferSize = dwBufferUsed;
            pRenderedValues = (PEVT_VARIANT)malloc(dwBufferSize);
            if(pRenderedValues)
            {
                EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount);
            }
            else
            {
				wprintf(L"SW_ERROR: malloc failed with %lu\n", status);
                status = ERROR_OUTOFMEMORY;
                goto cleanup;
            }
        }

        if(ERROR_SUCCESS != (status = GetLastError()))
        {
            status = PrintError(L"EvtRender");
            goto cleanup;
        }
    }

    // Event Record ID
	wprintf(L"EventRecordID: %I64u\n", pRenderedValues[EvtSystemEventRecordId].UInt64Val);

    // Time Created - convert to local time
	ullTimeStamp = pRenderedValues[EvtSystemTimeCreated].FileTimeVal;
    ft.dwHighDateTime = (DWORD)((ullTimeStamp >> 32) & 0xFFFFFFFF);
    ft.dwLowDateTime = (DWORD)(ullTimeStamp & 0xFFFFFFFF);
    FileTimeToSystemTime(&ft, &stUTC);
    SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);
    wprintf(L"TimeCreated SystemTime: %02d-%02d-%02d %02d:%02d:%02d\n", 
        stLocal.wYear, stLocal.wMonth, stLocal.wDay, stLocal.wHour, stLocal.wMinute, stLocal.wSecond);

    // Event ID
	DWORD EventID = pRenderedValues[EvtSystemEventID].UInt16Val;
    wprintf(L"EventID: %lu\n", EventID);

	// Level
    wprintf(L"Level: %u\n", (EvtVarTypeNull == pRenderedValues[EvtSystemLevel].Type) ? 0 : pRenderedValues[EvtSystemLevel].ByteVal);

    // Provider Name
	LPCWSTR pwsProviderName =pRenderedValues[EvtSystemProviderName].StringVal;
	wprintf(L"Provider Name: %s\n", pwsProviderName);

    // Computer
	wprintf(L"Computer: %s\n", pRenderedValues[EvtSystemComputer].StringVal);

    // Username & Domain
	if(EvtVarTypeNull != pRenderedValues[EvtSystemUserID].Type)
    {
		if( !LookupAccountSidW(NULL, pRenderedValues[EvtSystemUserID].SidVal,
                              lpName, &dwSize, lpDomain, 
                              &dwSize, &SidType)) 
		{
			wcscpy(lpName, L"N/A");
			wcscpy(lpDomain, L"N/A");
		}
		wprintf(L"Username: %s\n", lpName);
		wprintf(L"Domain: %s\n", lpDomain);
    }

    // Get the handle to the provider's metadata that contains the message strings.
    hProviderMetadata = EvtOpenPublisherMetadata(hRemote, pwsProviderName, NULL, 0, 0);
    if(NULL == hProviderMetadata)
    {
        status = PrintError(L"EvtOpenPublisherMetadata");
        goto cleanup;
    }

    // Get the various message strings from the event.
    pwsMessage = GetMessageString(hProviderMetadata, hEvent, EvtFormatMessageEvent);
    if(pwsMessage)
    {
        wprintf(L"Event message string: %s\n\n", pwsMessage);
        free(pwsMessage);
        pwsMessage = NULL;
    }

	pwsMessage = GetMessageString(hProviderMetadata, hEvent, EvtFormatMessageLevel);
    if(pwsMessage)
    {
    	wprintf(L"Level message string: %s\n\n", pwsMessage);
    	free(pwsMessage);
		pwsMessage = NULL;
    }

    pwsMessage = GetMessageString(hProviderMetadata, hEvent, EvtFormatMessageTask);
    if(pwsMessage != NULL)
    {
        wprintf(L"Task message string: %s\n\n", pwsMessage);
        free(pwsMessage);
        pwsMessage = NULL;
    }

    pwsMessage = GetMessageString(hProviderMetadata, hEvent, EvtFormatMessageOpcode);
    if(pwsMessage != NULL)
    {
        wprintf(L"Opcode message string: %s\n\n", pwsMessage);
        free(pwsMessage);
        pwsMessage = NULL;
    }

    pwsMessage = GetMessageString(hProviderMetadata, hEvent, EvtFormatMessageKeyword);
    if(pwsMessage)
    {
        LPWSTR ptemp = pwsMessage;
        wprintf(L"Keyword message string: %s", ptemp);

        while(*(ptemp += wcslen(ptemp)+1))
            wprintf(L", %s", ptemp);

        wprintf(L"\n\n");
        free(pwsMessage);
        pwsMessage = NULL;
    }

    pwsMessage = GetMessageString(hProviderMetadata, hEvent, EvtFormatMessageChannel);
    if(pwsMessage)
    {
        wprintf(L"Channel message string: %s\n\n", pwsMessage);
        free(pwsMessage);
        pwsMessage = NULL;
    }

    pwsMessage = GetMessageString(hProviderMetadata, hEvent, EvtFormatMessageProvider);
    if(pwsMessage)
    {
        wprintf(L"Provider message string: %s\n\n", pwsMessage);
        free(pwsMessage);
        pwsMessage = NULL;
    }

    pwsMessage = GetMessageString(hProviderMetadata, hEvent, EvtFormatMessageXml);
    if(pwsMessage)
    {
        wprintf(L"XML message string: %s\n\n", pwsMessage);
        free(pwsMessage);
        pwsMessage = NULL;
    }


cleanup:

    if(hContext)
        EvtClose(hContext);

    if(pRenderedValues)
        free(pRenderedValues);

    if(hProviderMetadata)
        EvtClose(hProviderMetadata);

    return status;
}

DWORD PrintEventData(EVT_HANDLE hEvent)
{
    DWORD status = ERROR_SUCCESS;
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    DWORD dwPropertyCount = 0;
    LPWSTR pRenderedContent = NULL;

    // The EvtRenderEventXml flag tells EvtRender to render the event as an XML string.
    if(!EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount))
    {
        if(ERROR_INSUFFICIENT_BUFFER == (status = GetLastError()))
        {
            dwBufferSize = dwBufferUsed;
            pRenderedContent = (LPWSTR)malloc(dwBufferSize);
            if(pRenderedContent)
            {
                EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount);
            }
            else
            {
                wprintf(L"malloc failed\n");
                status = ERROR_OUTOFMEMORY;
                goto cleanup;
            }
        }

        if(ERROR_SUCCESS != (status = GetLastError()))
        {
            wprintf(L"EvtRender failed with %d\n", GetLastError());
            goto cleanup;
        }
    }

    wprintf(L"\n\n%s", pRenderedContent);

cleanup:

    if(pRenderedContent)
        free(pRenderedContent);

    return status;
}

DWORD PrintEventSystemData(EVT_HANDLE hEvent)
{
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hContext = NULL;
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    DWORD dwPropertyCount = 0;
    PEVT_VARIANT pRenderedValues = NULL;
    WCHAR wsGuid[50];
    LPWSTR pwsSid = NULL;
    ULONGLONG ullTimeStamp = 0;
    ULONGLONG ullNanoseconds = 0;
    SYSTEMTIME st;
    FILETIME ft;

    // Identify the components of the event that you want to render. In this case,
    // render the system section of the event.
    hContext = EvtCreateRenderContext(0, NULL, EvtRenderContextSystem);
    if(NULL == hContext)
    {
        wprintf(L"EvtCreateRenderContext failed with %lu\n", status = GetLastError());
        goto cleanup;
    }

    // When you render the user data or system section of the event, you must specify
    // the EvtRenderEventValues flag. The function returns an array of variant values 
    // for each element in the user data or system section of the event. For user data
    // or event data, the values are returned in the same order as the elements are 
    // defined in the event. For system data, the values are returned in the order defined
    // in the EVT_SYSTEM_PROPERTY_ID enumeration.
    if(!EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount))
    {
        if(ERROR_INSUFFICIENT_BUFFER == (status = GetLastError()))
        {
            dwBufferSize = dwBufferUsed;
            pRenderedValues = (PEVT_VARIANT)malloc(dwBufferSize);
            if(pRenderedValues)
            {
                EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount);
            }
            else
            {
                wprintf(L"malloc failed\n");
                status = ERROR_OUTOFMEMORY;
                goto cleanup;
            }
        }

        if(ERROR_SUCCESS != (status = GetLastError()))
        {
            wprintf(L"EvtRender failed with %d\n", GetLastError());
            goto cleanup;
        }
    }

    // Print the values from the System section of the element.
    wprintf(L"Provider Name: %s\n", pRenderedValues[EvtSystemProviderName].StringVal);
    if(NULL != pRenderedValues[EvtSystemProviderGuid].GuidVal)
    {
        StringFromGUID2(*(pRenderedValues[EvtSystemProviderGuid].GuidVal), wsGuid, sizeof(wsGuid)/sizeof(WCHAR));
        wprintf(L"Provider Guid: %s\n", wsGuid);
    }
    else 
    {
        wprintf(L"Provider Guid: NULL");
    }


    DWORD EventID = pRenderedValues[EvtSystemEventID].UInt16Val;
    if(EvtVarTypeNull != pRenderedValues[EvtSystemQualifiers].Type)
    {
        EventID = MAKELONG(pRenderedValues[EvtSystemEventID].UInt16Val, pRenderedValues[EvtSystemQualifiers].UInt16Val);
    }
    wprintf(L"EventID: %lu\n", EventID);

    wprintf(L"Version: %u\n", (EvtVarTypeNull == pRenderedValues[EvtSystemVersion].Type) ? 0 : pRenderedValues[EvtSystemVersion].ByteVal);
    wprintf(L"Level: %u\n", (EvtVarTypeNull == pRenderedValues[EvtSystemLevel].Type) ? 0 : pRenderedValues[EvtSystemLevel].ByteVal);
    wprintf(L"Task: %hu\n", (EvtVarTypeNull == pRenderedValues[EvtSystemTask].Type) ? 0 : pRenderedValues[EvtSystemTask].UInt16Val);
    wprintf(L"Opcode: %u\n", (EvtVarTypeNull == pRenderedValues[EvtSystemOpcode].Type) ? 0 : pRenderedValues[EvtSystemOpcode].ByteVal);
    wprintf(L"Keywords: 0x%I64x\n", pRenderedValues[EvtSystemKeywords].UInt64Val);

    ullTimeStamp = pRenderedValues[EvtSystemTimeCreated].FileTimeVal;
    ft.dwHighDateTime = (DWORD)((ullTimeStamp >> 32) & 0xFFFFFFFF);
    ft.dwLowDateTime = (DWORD)(ullTimeStamp & 0xFFFFFFFF);
    
    FileTimeToSystemTime(&ft, &st);
    ullNanoseconds = (ullTimeStamp % 10000000) * 100; // Display nanoseconds instead of milliseconds for higher resolution
    wprintf(L"TimeCreated SystemTime: %02d/%02d/%02d %02d:%02d:%02d.%I64u)\n", 
        st.wMonth, st.wDay, st.wYear, st.wHour, st.wMinute, st.wSecond, ullNanoseconds);

	wprintf(L"EventRecordID: %I64u\n", pRenderedValues[EvtSystemEventRecordId].UInt64Val);

    if(EvtVarTypeNull != pRenderedValues[EvtSystemActivityID].Type)
    {
        StringFromGUID2(*(pRenderedValues[EvtSystemActivityID].GuidVal), wsGuid, sizeof(wsGuid)/sizeof(WCHAR));
        wprintf(L"Correlation ActivityID: %s\n", wsGuid);
    }

    if(EvtVarTypeNull != pRenderedValues[EvtSystemRelatedActivityID].Type)
    {
        StringFromGUID2(*(pRenderedValues[EvtSystemRelatedActivityID].GuidVal), wsGuid, sizeof(wsGuid)/sizeof(WCHAR));
        wprintf(L"Correlation RelatedActivityID: %s\n", wsGuid);
    }

    wprintf(L"Execution ProcessID: %lu\n", pRenderedValues[EvtSystemProcessID].UInt32Val);
    wprintf(L"Execution ThreadID: %lu\n", pRenderedValues[EvtSystemThreadID].UInt32Val);
    wprintf(L"Channel: %s\n", (EvtVarTypeNull == pRenderedValues[EvtSystemChannel].Type) ? L"" : pRenderedValues[EvtSystemChannel].StringVal);
    wprintf(L"Computer: %s\n", pRenderedValues[EvtSystemComputer].StringVal);

    if(EvtVarTypeNull != pRenderedValues[EvtSystemUserID].Type)
    {
        if(ConvertSidToStringSidW(pRenderedValues[EvtSystemUserID].SidVal, &pwsSid))
        {
            wprintf(L"Security UserID: %s\n", pwsSid);
            LocalFree(pwsSid);
        }
    }

cleanup:

    if(hContext)
        EvtClose(hContext);

    if(pRenderedValues)
        free(pRenderedValues);

    return status;
}

DWORD PrintEventValues(EVT_HANDLE hEvent)
{
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hContext = NULL;
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    DWORD dwPropertyCount = 0;
    PEVT_VARIANT pRenderedValues = NULL;
    LPWSTR ppValues[] = {L"Event/System/Provider/@Name", L"Event/System/Channel"};
    DWORD count = sizeof(ppValues)/sizeof(LPWSTR);

    // Identify the components of the event that you want to render. In this case,
    // render the provider's name and channel from the system section of the event.
    // To get user data from the event, you can specify an expression such as
    // L"Event/EventData/Data[@Name=\"<data name goes here>\"]".
    hContext = EvtCreateRenderContext(count, (LPCWSTR*)ppValues, EvtRenderContextValues);
    if(NULL == hContext)
    {
        wprintf(L"EvtCreateRenderContext failed with %lu\n", status = GetLastError());
        goto cleanup;
    }

    // The function returns an array of variant values for each element or attribute that
    // you want to retrieve from the event. The values are returned in the same order as 
    // you requested them.
    if(!EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount))
    {
        if(ERROR_INSUFFICIENT_BUFFER == (status = GetLastError()))
        {
            dwBufferSize = dwBufferUsed;
            pRenderedValues = (PEVT_VARIANT)malloc(dwBufferSize);
            if(pRenderedValues)
            {
                EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount);
            }
            else
            {
                wprintf(L"malloc failed\n");
                status = ERROR_OUTOFMEMORY;
                goto cleanup;
            }
        }

        if(ERROR_SUCCESS != (status = GetLastError()))
        {
            wprintf(L"EvtRender failed with %d\n", GetLastError());
            goto cleanup;
        }
    }

    // Print the selected values.
    wprintf(L"\nProvider Name: %s\n", pRenderedValues[0].StringVal);
    wprintf(L"Channel: %s\n", (EvtVarTypeNull == pRenderedValues[1].Type) ? L"" : pRenderedValues[1].StringVal);

cleanup:

    if(hContext)
        EvtClose(hContext);

    if(pRenderedValues)
        free(pRenderedValues);

    return status;
}


DWORD GetEventRecordID(EVT_HANDLE hEvent)
{
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hContext = NULL;
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    DWORD dwPropertyCount = 0;
    PEVT_VARIANT pRenderedValues = NULL;
    LPWSTR ppValues[] = {L"Event/System/EventRecordID"};
    DWORD count = sizeof(ppValues)/sizeof(LPWSTR);
	DWORD eventrecordid = NULL;

    // Identify the components of the event that you want to render. In this case,
    // render the provider's name and channel from the system section of the event.
    // To get user data from the event, you can specify an expression such as
    // L"Event/EventData/Data[@Name=\"<data name goes here>\"]".
    hContext = EvtCreateRenderContext(count, (LPCWSTR*)ppValues, EvtRenderContextValues);
    if(NULL == hContext)
    {
		status = PrintError(L"EvtCreateRenderContext");
        goto cleanup;
    }

    // The function returns an array of variant values for each element or attribute that
    // you want to retrieve from the event. The values are returned in the same order as 
    // you requested them.
    if(!EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount))
    {
        if(ERROR_INSUFFICIENT_BUFFER == (status = GetLastError()))
        {
            dwBufferSize = dwBufferUsed;
            pRenderedValues = (PEVT_VARIANT)malloc(dwBufferSize);
            if(pRenderedValues)
            {
                EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount);
            }
            else
            {
				wprintf(L"SW_ERROR: malloc failed\n");
                status = ERROR_OUTOFMEMORY;
                goto cleanup;
            }
        }

        if(ERROR_SUCCESS != (status = GetLastError()))
        {
            wprintf(L"EvtRender failed with %d\n", status);
            goto cleanup;
        }
    }

    eventrecordid = (DWORD) pRenderedValues[0].UInt64Val;
	// Print the selected values.
    //wprintf(L"\nEvent Record ID: %I64u\n", pRenderedValues[0].UInt64Val);

cleanup:

    if(hContext)
        EvtClose(hContext);

    if(pRenderedValues)
        free(pRenderedValues);

    return eventrecordid;
}


