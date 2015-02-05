#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#ifdef _MSC_VER
const wchar_t * strp_weekdays[] = 
    { L"sunday", L"monday", L"tuesday", L"wednesday", L"thursday", L"friday", L"saturday" };
const wchar_t * strp_monthnames[] = 
{ L"january", L"february", L"march", L"april", L"may", L"june", L"july", L"august", L"september", L"october", L"november", L"december" };
const wchar_t date_delimiter = L'-';
const wchar_t time_delimiter = L':';

bool atoi(const wchar_t * & s, WORD & result, int low, int high, int offset)
{
    bool worked = false;
    wchar_t * end;
    unsigned long num = wcstoul(s, & end, 10);
    if (num >= (unsigned long)low && num <= (unsigned long)high)
	{
        result = (int)(num + offset);
        s = end;
        worked = true;
	}
    return worked;
}

int FindTimeDiff(const wchar_t *date, const wchar_t *time, UINT64& timediff)
{
    SYSTEMTIME stLocal, stUTC, stNow;
	FILETIME ftUTC, ftNow;
	ULARGE_INTEGER ui, uiNow;

    if (*date && *time)
	{
		// Year
		if(!atoi(date, stLocal.wYear, 0, 65535, 0))
			return 1;

		// Date delimiter
		if (*date != date_delimiter)
			return 1;
		else
			++date;

		// Month
		if(!atoi(date, stLocal.wMonth, 1, 12, 0))
			return 1;

		// Date delimiter
		if (*date != date_delimiter)
			return 1;
		else
			++date;

		// Day
		if(!atoi(date, stLocal.wDay , 1, 31, 0))
			return 1;

		// Hours
		if(!atoi(time, stLocal.wHour, 0, 23, 0))
			return 1;

		// Time delimiter
		if (*time != time_delimiter)
			return 1;
		else
			++time;

		// Minutes
		if(!atoi(time, stLocal.wMinute, 0, 59, 0))
			return 1;

		// Time delimiter
		if (*time != time_delimiter)
			return 1;
		else
			++time;

		// Seconds
		if(!atoi(time, stLocal.wSecond, 0, 59, 0))
			return 1;

		TzSpecificLocalTimeToSystemTime(NULL, &stLocal, &stUTC);
		SystemTimeToFileTime(&stUTC,&ftUTC);
		ui.LowPart=ftUTC.dwLowDateTime;
		ui.HighPart=ftUTC.dwHighDateTime;

		GetSystemTime(&stNow);
		SystemTimeToFileTime(&stNow,&ftNow);
		uiNow.LowPart=ftNow.dwLowDateTime;
		uiNow.HighPart=ftNow.dwHighDateTime;
		timediff = (uiNow.QuadPart - ui.QuadPart)/10000;
	}
	return 0;
}


DWORD ConvertToFileTime(const wchar_t *date, const wchar_t *time, FILETIME& ft)
{
    SYSTEMTIME stLocal, stUTC;

    if (*date && *time)
	{
		// Year
		if(!atoi(date, stLocal.wYear, 0, 65535, 0))
			return 1;

		// Date delimiter
		if (*date != date_delimiter)
			return 1;
		else
			++date;

		// Month
		if(!atoi(date, stLocal.wMonth, 1, 12, 0))
			return 1;

		// Date delimiter
		if (*date != date_delimiter)
			return 1;
		else
			++date;

		// Day
		if(!atoi(date, stLocal.wDay , 1, 31, 0))
			return 1;

		// Hours
		if(!atoi(time, stLocal.wHour, 0, 23, 0))
			return 1;

		// Time delimiter
		if (*time != time_delimiter)
			return 1;
		else
			++time;

		// Minutes
		if(!atoi(time, stLocal.wMinute, 0, 59, 0))
			return 1;

		// Time delimiter
		if (*time != time_delimiter)
			return 1;
		else
			++time;

		// Seconds
		if(!atoi(time, stLocal.wSecond, 0, 59, 0))
			return 1;

		TzSpecificLocalTimeToSystemTime(NULL, &stLocal, &stUTC);
		SystemTimeToFileTime(&stUTC,&ft);
	}
	return 0;
}


bool strp_atoi(const wchar_t * & s, int & result, int low, int high, int offset)
    {
    bool worked = false;
    wchar_t * end;
    unsigned long num = wcstoul(s, & end, 10);
    if (num >= (unsigned long)low && num <= (unsigned long)high)
        {
        result = (int)(num + offset);
        s = end;
        worked = true;
        }
    return worked;
    }

char * strptime(const wchar_t *s, const wchar_t *format, struct tm *tm)
    {
    bool working = true;
    while (working && *format && *s)
        {
        switch (*format)
            {
        case '%':
            {
            ++format;
            switch (*format)
                {
            case 'a':
            case 'A': // weekday name
                tm->tm_wday = -1;
                working = false;
                for (size_t i = 0; i < 7; ++ i)
                    {
                    size_t len = wcslen(strp_weekdays[i]);
                    if (!_wcsnicmp(strp_weekdays[i], s, len))
                        {
                        tm->tm_wday = i;
                        s += len;
                        working = true;
                        break;
                        }
                    else if (!_wcsnicmp(strp_weekdays[i], s, 3))
                        {
                        tm->tm_wday = i;
                        s += 3;
                        working = true;
                        break;
                        }
                    }
                break;
            case 'b':
            case 'B':
            case 'h': // month name
                tm->tm_mon = -1;
                working = false;
                for (size_t i = 0; i < 12; ++ i)
                    {
                    size_t len = wcslen(strp_monthnames[i]);
                    if (!_wcsnicmp(strp_monthnames[i], s, len))
                        {
                        tm->tm_mon = i;
                        s += len;
                        working = true;
                        break;
                        }
                    else if (!_wcsnicmp(strp_monthnames[i], s, 3))
                        {
                        tm->tm_mon = i;
                        s += 3;
                        working = true;
                        break;
                        }
                    }
                break;
            case 'd':
            case 'e': // day of month number
                working = strp_atoi(s, tm->tm_mday, 1, 31, -1);
                break;
            case 'D': // %m/%d/%y
                {
                const wchar_t * s_save = s;
                working = strp_atoi(s, tm->tm_mon, 1, 12, -1);
                if (working && *s == '/')
                    {
                    ++ s;
                    working = strp_atoi(s, tm->tm_mday, 1, 31, -1);
                    if (working && *s == '/')
                        {
                        ++ s;
                        working = strp_atoi(s, tm->tm_year, 0, 99, 0);
                        if (working && tm->tm_year < 69)
                            tm->tm_year += 100;
                        }
                    }
                if (!working)
                    s = s_save;
                }
                break;
            case 'H': // hour
                working = strp_atoi(s, tm->tm_hour, 0, 23, 0);
                break;
            case 'I': // hour 12-hour clock
                working = strp_atoi(s, tm->tm_hour, 1, 12, 0);
                break;
            case 'j': // day number of year
                working = strp_atoi(s, tm->tm_yday, 1, 366, -1);
                break;
            case 'm': // month number
                working = strp_atoi(s, tm->tm_mon, 1, 12, -1);
                break;
            case 'M': // minute
                working = strp_atoi(s, tm->tm_min, 0, 59, 0);
                break;
            case 'n': // arbitrary whitespace
            case 't':
                while (isspace((int)*s)) 
                    ++s;
                break;
            case 'p': // am / pm
				if (!_wcsnicmp(s, L"am", 2))
                    { // the hour will be 1 -> 12 maps to 12 am, 1 am .. 11 am, 12 noon 12 pm .. 11 pm
                    if (tm->tm_hour == 12) // 12 am == 00 hours
                        tm->tm_hour = 0;
                    }
                else if (!_wcsnicmp(s, L"pm", 2))
                    {
                    if (tm->tm_hour < 12) // 12 pm == 12 hours
                        tm->tm_hour += 12; // 1 pm -> 13 hours, 11 pm -> 23 hours
                    }
                else
                    working = false;
                break;
            case 'r': // 12 hour clock %I:%M:%S %p
                {
                const wchar_t * s_save = s;
                working = strp_atoi(s, tm->tm_hour, 1, 12, 0);
                if (working && *s == L':')
                    {
                    ++ s;
                    working = strp_atoi(s, tm->tm_min, 0, 59, 0);
                    if (working && *s == L':')
                        {
                        ++ s;
                        working = strp_atoi(s, tm->tm_sec, 0, 60, 0);
                        if (working && isspace((int)*s))
                            {
                            ++ s;
                            while (isspace((int)*s)) 
                                ++s;
                            if (!_wcsnicmp(s, L"am", 2))
                                { // the hour will be 1 -> 12 maps to 12 am, 1 am .. 11 am, 12 noon 12 pm .. 11 pm
                                if (tm->tm_hour == 12) // 12 am == 00 hours
                                    tm->tm_hour = 0;
                                }
                            else if (!_wcsnicmp(s, L"pm", 2))
                                {
                                if (tm->tm_hour < 12) // 12 pm == 12 hours
                                    tm->tm_hour += 12; // 1 pm -> 13 hours, 11 pm -> 23 hours
                                }
                            else
                                working = false;
                            }
                        }
                    }
                if (!working)
                    s = s_save;
                }
                break;
            case 'R': // %H:%M
                {
                const wchar_t * s_save = s;
                working = strp_atoi(s, tm->tm_hour, 0, 23, 0);
                if (working && *s == L':')
                    {
                    ++ s;
                    working = strp_atoi(s, tm->tm_min, 0, 59, 0);
                    }
                if (!working)
                    s = s_save;
                }
                break;
            case 'S': // seconds
                working = strp_atoi(s, tm->tm_sec, 0, 60, 0);
                break;
            case 'T': // %H:%M:%S
                {
                const wchar_t * s_save = s;
                working = strp_atoi(s, tm->tm_hour, 0, 23, 0);
                if (working && *s == L':')
                    {
                    ++ s;
                    working = strp_atoi(s, tm->tm_min, 0, 59, 0);
                    if (working && *s == L':')
                        {
                        ++ s;
                        working = strp_atoi(s, tm->tm_sec, 0, 60, 0);
                        }
                    }
                if (!working)
                    s = s_save;
                }
                break;
            case 'w': // weekday number 0->6 sunday->saturday
                working = strp_atoi(s, tm->tm_wday, 0, 6, 0);
                break;
            case 'Y': // year
                working = strp_atoi(s, tm->tm_year, 1900, 65535, -1900);
                break;
            case 'y': // 2-digit year
                working = strp_atoi(s, tm->tm_year, 0, 99, 0);
                if (working && tm->tm_year < 69)
                    tm->tm_year += 100;
                break;
            case '%': // escaped
                if (*s != '%')
                    working = false;
                ++s;
                break;
            default:
                working = false;
                }
            }
            break;
        case ' ':
        case '\t':
        case '\r':
        case '\n':
        case '\f':
        case '\v':
            // zero or more whitespaces:
            while (isspace((int)*s))
                ++ s;
            break;
        default:
            // match character
            if (*s != *format)
                working = false;
            else
                ++s;
            break;
            }
        ++format;
        }
    return (working?(char *)s:0);
    }

#endif // _MSC_VER