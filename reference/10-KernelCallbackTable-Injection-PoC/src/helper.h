#pragma once

#define COLOR_RESET "\033[0m"
#define COLOR_RED_BOLD "\033[1;31m"
#define COLOR_GREEN_BOLD "\033[1;32m"
#define COLOR_YELLOW_BOLD "\033[1;32m"
#define COLOR_BLUE_BOLD "\033[1;34m"

extern PVOID LocatePEB();
extern PVOID ResolveKernelCallbackTable( PVOID PebAddress );
extern void WriteKernelCallbackTable( PVOID PebAddress, PVOID NewKernelCallbackTable );

#define MAX_WAIT_TIME 10000
