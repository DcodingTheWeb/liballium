#ifndef ALLIUM_H
#define ALLIUM_H

#include <stdbool.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

// SHA1 digest length
#define DIGEST_LEN 20

// Length of RFC2440-style S2K specifier: the first 8 bytes are a salt,
// the 9th describes how much iteration needs to be performed.
#define S2K_SPECIFIER_LEN 9

// Length of the final hashed key
#define KEY_LEN DIGEST_LEN + S2K_SPECIFIER_LEN

#ifdef _WIN32
typedef HANDLE allium_pipe;
#else
typedef int allium_pipe;
#endif

enum allium_status {RUNNING, DATA_AVAILABLE, STOPPED};

struct TorInstance {
	#ifdef _WIN32
	STARTUPINFO startup_info;
	PROCESS_INFORMATION process;
	#else
	int exit_code;
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
enum allium_status allium_get_status(struct TorInstance *instance);
bool allium_wait_for_output(struct TorInstance *instance, int timeout);
char *allium_read_stdout_line(struct TorInstance *instance);
int allium_get_exit_code(struct TorInstance *instance);
char *allium_hash(char *password);
void allium_clean(struct TorInstance *instance);

#endif
