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

bool allium_start(struct TorInstance *instance, char *config, allium_pipe *output_pipes) {
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
	instance->startup_info.dwFlags = STARTF_USESTDHANDLES;
	
	SECURITY_ATTRIBUTES pipe_secu_attribs = {sizeof(SECURITY_ATTRIBUTES), NULL, true};
	
	HANDLE pipes[2];
	if (output_pipes == NULL) {
		CreatePipe(&pipes[0], &pipes[1], &pipe_secu_attribs, 0);
		output_pipes = pipes;
	}
	instance->startup_info.hStdOutput = output_pipes[1];
	instance->startup_info.hStdError = output_pipes[1];
	instance->stdout_pipe = output_pipes[0]; // Stored for internal reference
	
	if (config) {
		// Reuse the pipes array to store standard input pipes
		CreatePipe(&pipes[0], &pipes[1], &pipe_secu_attribs, 0);
		instance->startup_info.hStdInput = pipes[0];
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
		WriteFile(pipes[1], config, strlen(config), &bytes_written, NULL);
		// Work around for simulating Ctrl + Z which sends the substitution character (ASCII 26),
		// this is needed in order for Tor to detect EOT/EOF while reading the config
		WriteFile(pipes[1], &(char){26}, 1, &bytes_written, NULL);
	}
	CloseHandle(pipes[1]);
	
	// Return on failure
	if (!success) return false;
	
	#else
	
	// Figure out the command arguments
	int input_pipes[2];
	char *cmd[config ? 4 : 2];
	cmd[0] = instance->tor_path;
	if (config) {
		if (pipe(input_pipes) == -1) return false;
		cmd[1] = "-f";
		cmd[2] = "-";
	}
	cmd[config ? 3 : 1] = NULL;
	
	// Prepare the output pipes
	int pipes[2];
	if (output_pipes == NULL) {
		if (pipe(pipes) == -1) return false;
		output_pipes = pipes;
	}
	instance->stdout_pipe = output_pipes[0]; // Stored for internal reference
	
	// Fork the process
	pid_t pid = fork();
	switch (pid) {
		case -1:
			// Fork has failed so return
			return false;
		case 0:
			if (config) {
				// Close the write end of the stdin pipe
				close(input_pipes[1]);
				// Duplicate our input and output pipes as stdio and exit on failure
				if (dup2(input_pipes[0], STDIN_FILENO) == -1) _Exit(EXIT_FAILURE);
			}
			// Route STDOUT and STDERR to our output pipe
			close(output_pipes[0]);
			if (
				dup2(output_pipes[1], STDOUT_FILENO) == -1 ||
				dup2(output_pipes[1], STDERR_FILENO) == -1
			) _Exit(EXIT_FAILURE);
			
			// Execute Tor by replacing our child's process
			execvp(instance->tor_path, cmd);
			_Exit(EXIT_FAILURE);
	}
	// Close the unneeded pipes
	if (config) close(input_pipes[0]);
	close(output_pipes[1]);
	
	// Pipe the config into the child process's stdin
	write(input_pipes[1], config, strlen(config));
	close(input_pipes[1]);
	#endif
	
	// Populate internal PID member in our instance for easier tracking
	#ifdef _WIN32
	instance->pid = instance->process.dwProcessId;
	#else
	instance->pid = pid;
	#endif
	return true;
}
