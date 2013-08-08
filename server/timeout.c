#ifdef WIN32

#include <windows.h>
#include <stdio.h>

#include "timeout.h"

__declspec( thread ) HANDLE gDoneEvent;
__declspec( thread ) static HANDLE hTimer;
__declspec( thread ) static HANDLE hTimerQueue;

VOID CALLBACK TimerRoutine(int* socket)
{
	int retval = 0;
	if( 0 != closesocket(*socket) )
	{
		//retval = WSAGetLastError();
		//printf("WAOOOOOOOOOOO COULDNT CLOSE IT: returned %d \n", retval);
		//printf("the socket was %d or %d", *socket);
	}
}

int timeoutSetup(int waittime, int* socket)
{
	hTimer = NULL;
	hTimerQueue = NULL;

	// Use an event object to track the TimerRoutine execution
	gDoneEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (NULL == gDoneEvent)
	{
		//printf("CreateEvent failed (%d)\n", GetLastError());
		return -1;
	}

	// Create the timer queue.
	hTimerQueue = CreateTimerQueue();
	if (NULL == hTimerQueue)
	{
		//printf("CreateTimerQueue failed (%d)\n", GetLastError());
		return -1;
	}

	// Set a timer to call the timer routine in 10 seconds.
	if (!CreateTimerQueueTimer( &hTimer, hTimerQueue, 
		(WAITORTIMERCALLBACK)TimerRoutine, socket , waittime, 0, 0))
	{
		//printf("CreateTimerQueueTimer failed (%d)\n", GetLastError());
		return -1;
	}


	return 0;
}

int endTimeout()
{
	CloseHandle(gDoneEvent);
	DeleteTimerQueue(hTimerQueue);
	return 0;
}

#endif	// WIN32
