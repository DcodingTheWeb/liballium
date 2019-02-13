#include <stdlib.h>
#include <string.h>
#include "allium.h"
#ifndef _WIN32
#include <sys/wait.h>
#endif

struct TorInstance *allium_new_instance(char *tor_path) {
	struct TorInstance *instance = malloc(sizeof(struct TorInstance));
	if (instance == NULL) return NULL;
	instance->tor_path = tor_path;
	instance->pid = 0;
	instance->buffer.size = 0;
	instance->buffer.data = NULL;
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
	SetHandleInformation(output_pipes[0], HANDLE_FLAG_INHERIT, 0);
	instance->startup_info.hStdOutput = output_pipes[1];
	instance->startup_info.hStdError = output_pipes[1];
	instance->stdout_pipe = output_pipes[0]; // Stored for internal reference
	
	HANDLE input_pipes[2];
	if (config) {
		CreatePipe(&input_pipes[0], &input_pipes[1], &pipe_secu_attribs, 0);
		SetHandleInformation(input_pipes[1], HANDLE_FLAG_INHERIT, 0);
		instance->startup_info.hStdInput = input_pipes[0];
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
	
	// Close the write end of our stdout handle
	CloseHandle(output_pipes[1]);
	
	if (config) {
		CloseHandle(input_pipes[0]); // Close the read end of our stdin handle
		free(cmd); // Free the command string
	}
	
	// Write config to Tor's standard input
	unsigned long bytes_written;
	if (success) {
		WriteFile(input_pipes[1], config, strlen(config), &bytes_written, NULL);
		// Work around for simulating Ctrl + Z which sends the substitution character (ASCII 26),
		// this is needed in order for Tor to detect EOT/EOF while reading the config
		WriteFile(input_pipes[1], &(char){26}, 1, &bytes_written, NULL);
	}
	CloseHandle(input_pipes[1]);
	
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

char *allium_read_stdout_line(struct TorInstance *instance) {
	char *buffer = instance->buffer.data;
	
	// Check for valid buffer and allocate if needed
	if (instance->buffer.size == 0 || !buffer) {
		buffer = instance->buffer.data = malloc(instance->buffer.size = 80 + 1);
		if (!buffer) return NULL;
	}
	
	// Process the input
	unsigned int read_len = 0;
	while (true) {
		// Read data
		#ifdef _WIN32
		unsigned long bytes_read;
		if (ReadFile(instance->stdout_pipe, buffer, 1, &bytes_read, NULL) == false || bytes_read == 0) return NULL;
		#else
		if (read(instance->stdout_pipe, buffer, 1) <= 0) return NULL;
		#endif
		
		// Check if we have reached end of line
		if (buffer[0] == '\n') break;
		
		// Proceed to the next character
		++buffer; ++read_len;
		
		// Resize buffer if it is full
		if (read_len == instance->buffer.size) {
			char *new_buffer = malloc(instance->buffer.size += 50);
			if (new_buffer) memcpy(new_buffer, instance->buffer.data, read_len);
			free(instance->buffer.data);
			if (!new_buffer) return NULL;
			instance->buffer.data = new_buffer;
			buffer = instance->buffer.data + read_len;
		}
	}
	
	// Terminate the new line with null character and return
	#ifdef _WIN32
	// Special handling for Windows, terminate at CR if present
	buffer[read_len >= 2 && buffer[-1] == '\r' ? -1 : 0] = '\0';
	#else
	buffer[0] = '\0';
	#endif
	return instance->buffer.data;
}

int allium_get_exit_code(struct TorInstance *instance) {
	#ifdef _WIN32
	unsigned long exit_code;
	bool success = GetExitCodeProcess(instance->process.hProcess, &exit_code);
	if (!success) return -1;
	return exit_code;
	#else
	int status;
	waitpid(instance->pid, &status, 0);
	return WEXITSTATUS(status);
	#endif
}
