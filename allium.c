#include <stdlib.h>
#include "allium.h"

struct TorInstance *allium_new_instance(char *tor_path) {
	struct TorInstance *instance = malloc(sizeof(struct TorInstance));
	if (instance == NULL) return NULL;
	instance->tor_path = tor_path;
	instance->pid = 0;
	return instance;
}

bool allium_start(struct TorInstance *instance) {
	#ifdef _WIN32
	bool success = CreateProcessA(
		NULL,
		instance->tor_path,
		NULL,
		NULL,
		false,
		0,
		NULL,
		NULL,
		SecureZeroMemory(&instance->startup_info, sizeof instance->startup_info),
		SecureZeroMemory(&instance->process, sizeof instance->process)
	);
	if (!success) return false;
	instance->pid = instance->process.dwProcessId;
	return true;
	#else
	pid_t pid = fork();
	switch (pid) {
		case -1:
			return false;
		case 0:
			execl(instance->tor_path, instance->tor_path, "", NULL);
			_Exit(EXIT_FAILURE);
	}
	instance->pid = pid;
	return true;
	#endif
}
