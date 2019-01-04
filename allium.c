#include <stdlib.h>
#include <string.h>
#include "allium.h"

struct TorInstance *allium_new_instance(char *tor_path) {
	struct TorInstance *instance = malloc(sizeof(struct TorInstance));
	if (instance == NULL) return NULL;
	instance->tor_path = tor_path;
	instance->pid = 0;
	return instance;
}

bool allium_start(struct TorInstance *instance, char *config) {
	#ifdef _WIN32
	char *cmd;
	
	// Figure out the command string for execution
	if (config) {
		char *parameters = " -f -";
		cmd = malloc(strlen(instance->tor_path) + strlen(parameters) + 1);
		if (!cmd) return false;
		strcpy(cmd, instance->tor_path);
		strcat(cmd, parameters);
	} else cmd = instance->tor_path;
	
	// Prepare startup info with appropriate information
	SecureZeroMemory(&instance->startup_info, sizeof instance->startup_info);
	HANDLE read_pipe, write_pipe;
	if (config) {
		CreatePipe(&read_pipe, &write_pipe, &(SECURITY_ATTRIBUTES){sizeof(SECURITY_ATTRIBUTES), NULL, true}, 0);
		instance->startup_info.dwFlags = STARTF_USESTDHANDLES;
		instance->startup_info.hStdInput = read_pipe;
	}
	
	// Create the process
	bool success = CreateProcessA(
		NULL,
		cmd,
		NULL,
		NULL,
		config ? true : false,
		0,
		NULL,
		NULL,
		&instance->startup_info,
		SecureZeroMemory(&instance->process, sizeof instance->process)
	);
	
	// Free command string if needed
	if (config) free(cmd);
	
	// Write config to Tor's standard input
	unsigned long bytes_written;
	if (success) {
		WriteFile(write_pipe, config, strlen(config), &bytes_written, NULL);
		// Work around for simulating Ctrl + Z which sends the substitution character (ASCII 26),
		// this is needed in order for Tor to detect EOT/EOF while reading the config
		WriteFile(write_pipe, &(char){26}, 1, &bytes_written, NULL);
	}
	CloseHandle(write_pipe);
	
	// Return on failure
	if (!success) return false;
	#else
	// Figure out the command arguments
	int filedes[2];
	char *cmd[config ? 4 : 2];
	cmd[0] = instance->tor_path;
	if (config) {
		if (pipe(filedes) == -1) return false;
		cmd[1] = "-f";
		cmd[2] = "-";
	}
	cmd[config ? 3 : 1] = NULL;
	
	// Fork the process
	pid_t pid = fork();
	switch (pid) {
		case -1:
			// Fork has failed so return
			return false;
		case 0:
			if (config) {
				// Close the write end of the pipe
				close(filedes[1]);
				// Duplicate our read end of the pipe as stdin and exit on failure
				if (config && dup2(filedes[0], STDIN_FILENO) == -1) _Exit(EXIT_FAILURE);
			}
			// Execute Tor by replacing our child's process
			execvp(instance->tor_path, cmd);
			_Exit(EXIT_FAILURE);
	}
	
	// Pipe the config into the child process's stdin
	close(filedes[0]);
	write(filedes[1], config, strlen(config));
	close(filedes[1]);
	#endif
	
	// Populate internal PID member in our instance for easier tracking
	#ifdef _WIN32
	instance->pid = instance->process.dwProcessId;
	#else
	instance->pid = pid;
	#endif
	return true;
}
