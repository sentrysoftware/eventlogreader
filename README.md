# EventLogReader

![GitHub release (with filter)](https://img.shields.io/github/v/release/sentrysoftware/eventlogreader)
![Build](https://img.shields.io/github/actions/workflow/status/sentrysoftware/eventlogreader/msbuild.yml)
![GitHub top language](https://img.shields.io/github/languages/top/sentrysoftware/eventlogreader)
![License](https://img.shields.io/github/license/sentrysoftware/eventlogreader)

High-performance command-line utility to query the Windows event logs, locally or remotely.

## Usage

```
EventLogReader,  Version 2.0.00,  Displays Windows event log content
                                         on Microsoft Windows 2008 and above
Usage:
  EventLogReader -help
  EventLogReader -version
  EventLogReader [<host>] [-u <username> -p <password>] -ListEventLogs
  EventLogReader [<host>:]<log> [-u <username> -p <password>]
                         -ListEventLogProviders
                         -GetNewestEventRecordNumber
                         -GetOldestEventRecordNumber
                         -Report <date> <time>
                         -Howmany <from> <to> [<criteria>]
                         -Dump <from> <to> [<criteria>]
                         -CompleteDump <from> <to> [<criteria>]

Where: <host>     is optional remote host name
       <username> is the optional login username for the remote host
       <password> is the optional login password for the remote host
       <log>      is the name of the event log: system|security|application
       <date>     is the starting date to be searched from in YYYY-MM-DD format
       <time>     is the starting time to be searched from in HH:MM:SS format
       <from>     is the starting event record number or 'oldest'
       <to>       is the ending event record number or 'newest'
       <criteria> is optional criteria to be used for filtering the events
                  supports: sourcename=<source name> category=<category>
                  id=<event ID> level=<event level> computer=<computername>
                  user=<username> domain=<domainname>

Output:
  -help          displays this usage information
  -version       reports the version details of this executable
  -ListEventLogs lists all registered event logs on the host
  -ListEventLogProviders       lists all registered event providers for the log
  -GetNewestEventRecordNumber  reports the newest event record number
  -GetOldestEventRecordNumber  reports the oldes event record number
  -Report        produces a pipe (|) delimited event report showing:
                 RecordNumber, TimeGenerated, ComputerName, Provider,
                 EventID, EventLevel & Message
  -HowMany       reports number of matching events found
  -Dump          produces a semicolon delimited report containing:
                 RecordNumber, TimeGenerated, EventID, EventLevel,
                 Provider, ComputerName, User, Domain & InsertionStrings
  -CompleteDump  produces a semicolon delimited report containing:
                 RecordNumber, TimeGenerated, EventID, EventLevel,
                 Provider, ComputerName, User, Domain & Message
```

## How to Build

To buils locally, you will need the Microsoft's [Build Tools for Visual Studio 2022](https://aka.ms/vs/17/release/vs_BuildTools.exe), 
with all C/C++ libraries and the Windows SDK.

You will need to run `vsdevcmd` to setup your build environment before you can compile this project, like in the example below:

```batch
"c:\\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\vsdevcmd.bat
```

Then, run the below command at the root of the repository to build the project:

```batch
msbuild /t:Rebuild /p:Configuration=Release .
```

This will produce one `EventLogReader.exe` artifact in the `./Release` folder.

## Contribute

Follow [Sentry Software contributing rules](https://sentrysoftware.org/contributing.html) and [Code of Conduct](https://sentrysoftware.org/code-of-conduct.html).
