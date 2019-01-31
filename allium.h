#ifndef ALLIUM_H
#define ALLIUM_H

#include <stdbool.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#ifdef _WIN32
typedef HANDLE allium_pipe;
#else
typedef int allium_pipe;
#endif

struct TorInstance {
	#ifdef _WIN32
	STARTUPINFO startup_info;
	PROCESS_INFORMATION process;
	#endif
	allium_pipe stdout_pipe;
	unsigned long pid;
	char *tor_path;
	struct {
		size_t size;
		char *data;
	} buffer;
};

struct TorInstance *allium_new_instance(char *tor_path);
bool allium_start(struct TorInstance *instance, char *config, allium_pipe *output_pipes);
char *allium_read_stdout_line(struct TorInstance *instance);

#endif
