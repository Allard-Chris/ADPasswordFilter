# ADPasswordFilter
---

## Description

Implementation of password filter functions in a DLL to provide password filtering.

**ADPasswordFilter.dll** add functions for:
- Filtering any password that contains words we don't want to see in it (like the company's name).
- Filtering any weak password that can be considered valid by default (like a leaked one on internet).

**ADPasswordFilterEventMessage.dll** is used to log all non-sensitive informations into EventLog in case of errors bad passwords. This is intended to help administrators diagnose problems when changing passwords.

## Note and remarks

The program is provided without any warranty.
I'm not going to compile it for every existing Windows platform and version.
If you find any error or vulnerability, please report them so that we can make the necessary changes and benefit everyone.

## How to install

See [INSTALL.md](.\INSTALL.md).

## How to uninstall

See [UNINSTALL.md](.\UNINSTALL.md).

## How to build

See [BUILD.md](.\BUILD.md).

## How it works

See [HOWITWORKS.md](.\HOWITWORKS.md).

## Microsoft documentations
- [Functions used for filtering password](https://learn.microsoft.com/da-dk/windows/win32/secmgmt/management-functions#password-filter-functions)
- [How to handle passwords](https://learn.microsoft.com/en-us/windows/win32/secbp/handling-passwords)
- [Naming conventions guide](https://learn.microsoft.com/en-us/dotnet/standard/design-guidelines/names-of-assemblies-and-dlls)
- [How to write in EventLog](https://learn.microsoft.com/en-us/windows/win32/eventlog/reporting-an-event)

## Github projects used as example
- [A DLL implementation by Jules Duvivier](https://github.com/julesduvivier/PasswordFilter/blob/master/PasswordFilter/dllmain.cpp)
- [Another implemantation](https://github.com/fblz/PassFilter/blob/master/PassFilter/PassFilter.cpp)

## Topics on this subject
- https://blog.carnal0wnage.com/2013/09/stealing-passwords-every-time-they.html
- https://redcanary.com/blog/atomic-friday-password-filters/
