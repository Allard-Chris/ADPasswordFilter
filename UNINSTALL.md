# How to uninstall
---

## 1 - Modifying LSA service registry

We need to disable the DLL in the LSA service.
In the registry, under 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA', modify the key named 'Notification Packages' and remove the line 'ADPasswordFilter'

## 2 - Reboot

In order for the LSA service to not take anymore the DLL into account, the server must be restarted.

## 3 - Remove DLLs and registry entrie

After the reboot, you can reverse all the steps in 'INSTALL.md' to completely uninstall the DLLs:
- Remove any entrie for ADPasswordFilter.
- Remove any entrie for ADPasswordFilterEventMessage.
- Delete 'ADPasswordFilter.dll' and 'ADPasswordFilterEventMessage.dll' under 'C:\Windows\System32\'
- Delete both dictionaries files.
