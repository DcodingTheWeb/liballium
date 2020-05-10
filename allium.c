#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "allium.h"
#ifndef _WIN32
#include <poll.h>
#include <sys/wait.h>
#endif
#ifdef FOUND_CRYPT
#include <tomcrypt.h>
#endif

// Internal functions
#ifdef FOUND_CRYPT
bool secret_to_key_rfc2440(unsigned char *key_out, size_t key_out_len, const char *secret, size_t secret_len, const unsigned char *s2k_specifier);
char *bin2hex(const unsigned char *bin, size_t len);
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

enum allium_status allium_get_status(struct TorInstance *instance, int timeout) {
	// Check if any data is available for reading in the buffer
	bool data_available = allium_wait_for_output(instance, timeout);
	if (data_available) return DATA_AVAILABLE;

	// Check if Tor is still running
	#ifdef _WIN32
	if (WaitForSingleObject(instance->process.hProcess, 0) == WAIT_TIMEOUT) {
		return RUNNING;
	} else {
		return STOPPED;
	}
	#else
	int status;
	if (waitpid(instance->pid, &status, WNOHANG) > 0) {
		instance->exit_code = WEXITSTATUS(status);
		return WIFEXITED(status) ? STOPPED : RUNNING;
	} else {
		return RUNNING;
	}
	#endif
}

bool allium_wait_for_output(struct TorInstance *instance, int timeout) {
	#ifdef _WIN32
	unsigned long start_time;
	if (timeout > 0) start_time = GetTickCount();
	unsigned long bytes_available;
	while (true) {
		bool success = PeekNamedPipe(instance->stdout_pipe, NULL, 0, NULL, &bytes_available, NULL);
		if (success && bytes_available > 0) return true;
		if (timeout > 0) {
			if (GetTickCount() - start_time > timeout) return false;
			Sleep(1);
		}
	}
	#else
	if (instance->stdout_pipe == -1) return false;
	struct pollfd poll_data = {.fd = instance->stdout_pipe, .events = POLLIN};
	int event_num = poll(&poll_data, 1, timeout);
	return event_num > 0 && !(poll_data.revents & POLLHUP);
	#endif
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
		ssize_t return_val = read(instance->stdout_pipe, buffer, 1);
		if (return_val <= 0) {
			if (return_val == 0) {
				/* EOF has been reached which means that the pipe has been closed on the other end.
				 * Most likely this means that Tor has exited, so close the pipe on our end and set
				 * the file descriptor to -1 so that it can later be checked if the pipe has been closed.
				 */
				close(instance->stdout_pipe);
				instance->stdout_pipe = -1;
			}
			return NULL;
		}
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
	return instance->exit_code;
	#endif
}

#ifdef FOUND_CRYPT
char *allium_hash(char *password) {
	unsigned char key[KEY_LEN];
	sprng_read(key, S2K_SPECIFIER_LEN - 1, NULL);
	key[S2K_SPECIFIER_LEN - 1] = 96;
	
	bool success = secret_to_key_rfc2440(
		key + S2K_SPECIFIER_LEN,
		DIGEST_LEN,
		password,
		strlen(password),
		key
	);
	if (!success) return NULL;
	
	char *key_string = bin2hex(key, KEY_LEN);
	if (!key_string) return NULL;
	
	char *hash_string = malloc(61);
	if (!hash_string) {
		free(key_string);
		return NULL;
	}
	
	strcpy(hash_string, "16:");
	strcat(hash_string, key_string);
	
	free(key_string);
	return hash_string;
}
#endif

void allium_clean(struct TorInstance *instance) {
	#ifdef _WIN32
	CloseHandle(instance->process.hProcess);
	CloseHandle(instance->process.hThread);
	CloseHandle(instance->stdout_pipe);
	#else
	if (instance->stdout_pipe != -1) close(instance->stdout_pipe);
	#endif
}

// Internal functions

#ifdef FOUND_CRYPT

bool secret_to_key_rfc2440(unsigned char *key_out, size_t key_out_len, const char *secret, size_t secret_len, const unsigned char *s2k_specifier) {
	char iteration_count = s2k_specifier[S2K_SPECIFIER_LEN - 1];
	#define EXPBIAS 6
	size_t count = ((uint32_t)16 + (iteration_count & 15)) << ((iteration_count >> 4) + EXPBIAS);
	#undef EXPBIAS
	
	// Allocate and populate the temporary buffer with data
	// This is the data which will be hashed
	char *temp = malloc((S2K_SPECIFIER_LEN - 1) + secret_len);
	memcpy(temp, s2k_specifier, S2K_SPECIFIER_LEN - 1);
	memcpy(temp + (S2K_SPECIFIER_LEN - 1), secret, secret_len);
	secret_len += S2K_SPECIFIER_LEN - 1;
	
	// Hash the data
	hash_state hash;
	if (sha1_init(&hash) != CRYPT_OK) return false;
	
	int result;
	while (count != 0) {
		if (count >= secret_len) {
			result = sha1_process(&hash, (unsigned char *) temp, secret_len);
			count -= secret_len;
		} else {
			result = sha1_process(&hash, (unsigned char *) temp, count);
			count = 0;
		}
		if (result != CRYPT_OK) return false;
	}
	free(temp);
	
	// Get the raw digest
	unsigned char digest[DIGEST_LEN];
	result = sha1_done(&hash, digest);
	if (result != CRYPT_OK) return false;
	
	// Copy the digest
	if (key_out_len <= DIGEST_LEN) {
		memcpy(key_out, digest, key_out_len);
		return true;
	} else {
		// Key expansion is unsupported at the moment
		return false;
	}
}

// Forked from: https://nachtimwald.com/2017/09/24/hex-encode-and-decode-in-c/
char *bin2hex(const unsigned char *bin, size_t len) {
	if (bin == NULL || len == 0) return NULL;
	
	char *out = malloc(len*2+1);
	if (!out) return NULL;
	
	for (size_t i=0; i<len; i++) {
		out[i*2]   = "0123456789ABCDEF"[bin[i] >> 4];
		out[i*2+1] = "0123456789ABCDEF"[bin[i] & 0x0F];
	}
	out[len*2] = '\0';
	
	return out;
}

#endif
