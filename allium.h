#include <stdbool.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

struct TorInstance {
	#ifdef _WIN32
	STARTUPINFO startup_info;
	PROCESS_INFORMATION process;
	#endif
	unsigned long pid;
	char *tor_path;
};

struct TorInstance *allium_new_instance(char *tor_path);
bool allium_start(struct TorInstance *instance, char *config);
