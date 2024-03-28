# How to build
---

## Description

The project was created with 'Microsoft Visual Studio Community 2022'.
Be aware that an enterprise license is required from the moment the project is forked, modified and used without publishing the modifications.
However, a company can use this project to compile it, without the need for a license.

## Dependency

You must install the Microsoft Windows Software Development Kit (SDK) in order to have all headers and libraries necessary to compile and link the DLL.

## Compile

Open the solution with Microsoft Visual Studio.
Be sure that these options are enabled:
- Compile for x64 architecture.
- O2 optimisation.
- Runtime library: DLL multithread.

## Generate ADPasswordFilterEventMessage

The DLL use 'winapi' for writing logs in EventLog.
To generate 'ADPasswordFilterEventMessage.dll', you need to:

1. Open Visual Studio.
2. On the menu bar, select Tools > Command Line > Developer Command Prompt or Developer PowerShell.
3. Compile the file: ```mc -U ADPasswordFilterEventMessage.mc```
4. Compile the ressource generated before: ```rc ADPasswordFilterEventMessage.rc```
5. Create the DLL: ```link -dll -noentry ADPasswordFilterEventMessage.res```
