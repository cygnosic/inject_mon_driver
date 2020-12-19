#include <ntifs.h>


extern "C" {
	typedef
		VOID(*PCREATE_THREAD_NOTIFY_ROUTINE)(
			_In_ HANDLE ProcessId,
			_In_ HANDLE ThreadId,
			_In_ BOOLEAN Create
			);

	
EXTERN_C VOID Notifyifinjected(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create) {
	
		NTSTATUS status;
		PEPROCESS Process;
		LPCSTR lpProcess = NULL;
		HANDLE thisProcess = NULL;
		Create = TRUE;
		UNREFERENCED_PARAMETER(ThreadId);

		status = PsLookupProcessByProcessId(ProcessId, &Process);
		
		if (!NT_SUCCESS(status))
		{
			DbgPrint("PsLookupProcessByProcessId()\n");
			return;
		}

		thisProcess = PsGetCurrentProcessId();
		if (HandleToULong(thisProcess) == 4)  //ignore the system process   
		{
			return;
		}

		lpProcess = (LPTSTR)Process;
		lpProcess = (LPTSTR)(lpProcess + 0x5a8); // ImageFileName dt _EPROCESS  (could be different on your PC)

		if (thisProcess != ProcessId)
		{
			PEPROCESS iProcess;
			LPTSTR lpProcessIn;
			status = PsLookupProcessByProcessId(thisProcess, &iProcess);
			lpProcessIn = (LPTSTR)iProcess;
			lpProcessIn = (LPTSTR)(lpProcessIn + 0x5a8); // ImageFileName dt _EPROCESS (could be different on your PC)

			LPTSTR ActiveThreads = (LPTSTR)(lpProcess + 0x48); // ActiveThreads dt _EPROCESS

			if ((UINT32)*ActiveThreads > 1) // first thread always remote
				DbgPrint("[ALERT!!!!!] Remote Process %d (%s) was injected by Process %d (%s)\n", ProcessId, lpProcess, thisProcess, lpProcessIn);
		}
	}

NTSTATUS DriverEntry(
		PDRIVER_OBJECT DriverObject,
		PUNICODE_STRING RegistryPath
	) 
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS status;
	HANDLE ThisProcessId;
	
	ThisProcessId = PsGetCurrentProcess();
	
		status = PsSetCreateThreadNotifyRoutine(Notifyifinjected);
		if (!NT_SUCCESS(status)) {
			DbgPrint("failed:(status=%08X)\n", status);
		}
		return STATUS_SUCCESS;
	}

}
