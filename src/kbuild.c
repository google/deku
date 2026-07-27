/*
 * Copyright (c) 2024 Google LLC
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <limits.h>
#include <ctype.h>
#include <glob.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>
#include <regex.h>

#include "kbuild.h"
#include "libelfutils.h"

#ifndef TOOLCHAIN
#define TOOLCHAIN ""
#endif

#ifndef RED
#define RED "\x1b[31m"
#endif

#ifndef NC
#define NC "\x1b[0m"
#endif

Config config;

// Helper to trim whitespace from a string
static char *trimSpace(const char *str) {
	while (isspace((unsigned char)*str)) str++;
	if (*str == '\0') return strdup("");
	const char *end = str + strlen(str) - 1;
	while (end > str && isspace((unsigned char)*end)) end--;
	size_t len = end - str + 1;
	char *res = malloc(len + 1);
	memcpy(res, str, len);
	res[len] = '\0';
	return res;
}

// Helper to split string by whitespace into an array (fields)
static char **splitFields(const char *str, int *out_count) {
	int count = 0;
	int capacity = 10;
	char **res = malloc(capacity * sizeof(char*));
	
	const char *p = str;
	while (*p) {
		while (*p && isspace((unsigned char)*p)) p++;
		if (*p == '\0') break;
		const char *start = p;
		while (*p && !isspace((unsigned char)*p)) p++;
		size_t len = p - start;
		char *word = malloc(len + 1);
		memcpy(word, start, len);
		word[len] = '\0';
		
		if (count >= capacity) {
			capacity *= 2;
			res = realloc(res, capacity * sizeof(char*));
		}
		res[count++] = word;
	}
	*out_count = count;
	return res;
}

// Helper to read first line of a file
static char *readFirstLine(const char *filepath) {
	FILE *f = fopen(filepath, "r");
	if (!f) return NULL;
	char *line = NULL;
	size_t len = 0;
	ssize_t read = getline(&line, &len, f);
	fclose(f);
	if (read == -1) {
		free(line);
		return NULL;
	}
	while (read > 0 && (line[read - 1] == '\n' || line[read - 1] == '\r')) {
		line[read - 1] = '\0';
		read--;
	}
	return line;
}

char *filenameNoExt(const char *path) {
	const char *base = strrchr(path, '/');
	if (base) {
		base++;
	} else {
		base = path;
	}
	char *res = strdup(base);
	char *dot = strrchr(res, '.');
	if (dot) {
		*dot = '\0';
	}
	return res;
}

char *filepathDir(const char *path) {
	const char *slash = strrchr(path, '/');
	if (!slash) {
		return strdup(".");
	}
	if (slash == path) {
		return strdup("/");
	}
	size_t len = slash - path;
	char *res = malloc(len + 1);
	memcpy(res, path, len);
	res[len] = '\0';
	return res;
}

char *filepathJoin(const char *dir, const char *file) {
	size_t len_dir = strlen(dir);
	size_t len_file = strlen(file);
	char *res = malloc(len_dir + len_file + 2);
	strcpy(res, dir);
	if (len_dir > 0 && res[len_dir - 1] != '/') {
		strcat(res, "/");
	}
	strcat(res, file);
	return res;
}

bool fileExists(const char *path) {
	struct stat st;
	return stat(path, &st) == 0;
}

char *findPathForFileFromCmdFile(const char *path, const char *file) {
	char glob_pattern[PATH_MAX];
	snprintf(glob_pattern, sizeof(glob_pattern), "%s/*.o.cmd", path);
	
	glob_t glob_result;
	int g = glob(glob_pattern, 0, NULL, &glob_result);
	if (g != 0 || glob_result.gl_pathc == 0) {
		LOG_ERR("Can't find any *.o.cmd in the build dir: %s", path);
		globfree(&glob_result);
		return strdup("");
	}
	
	const char *cmd_file = glob_result.gl_pathv[0];
	FILE *f = fopen(cmd_file, "r");
	if (!f) {
		LOG_ERR("Can't open %s", cmd_file);
		globfree(&glob_result);
		return strdup("");
	}
	
	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	char *ret = strdup("");
	
	size_t file_len = strlen(file);
	char *suffix = malloc(file_len + 4); // file + " \\"
	snprintf(suffix, file_len + 4, "%s \\", file);
	
	while ((read = getline(&line, &len, f)) != -1) {
		while (read > 0 && (line[read - 1] == '\n' || line[read - 1] == '\r')) {
			line[read - 1] = '\0';
			read--;
		}
		
		size_t line_len = strlen(line);
		size_t suffix_len = strlen(suffix);
		if (line_len >= suffix_len && strcmp(line + line_len - suffix_len, suffix) == 0) {
			line[line_len - suffix_len] = '\0';
			char *trimmed = trimSpace(line);
			
			size_t trimmed_len = strlen(trimmed);
			if (trimmed_len >= file_len && strcmp(trimmed + trimmed_len - file_len, file) == 0) {
				trimmed[trimmed_len - file_len] = '\0';
				free(ret);
				ret = strdup(trimmed);
				free(trimmed);
				break;
			}
			free(trimmed);
		}
	}
	
	free(line);
	free(suffix);
	fclose(f);
	globfree(&glob_result);
	
	if (strlen(ret) == 0) {
		LOG_ERR("Can't find %s in the: %s", file, cmd_file);
	}
	return ret;
}

static int cmdFromMod(const char *modFile, char ***out_cmd, int *out_cmd_count, char **out_extraCmd) {
	*out_cmd = NULL;
	*out_cmd_count = 0;
	*out_extraCmd = strdup("");

	char *line = readFirstLine(modFile);
	if (!line) {
		return -1;
	}

	char *eq = strchr(line, '=');
	if (!eq) {
		free(line);
		return -1;
	}
	char *gccPart = eq + 1;

	char *semicolon = strchr(gccPart, ';');
	if (semicolon) {
		*semicolon = '\0';
		char *extra = semicolon + 1;
		free(*out_extraCmd);
		*out_extraCmd = trimSpace(extra);
	}

	int param_count = 0;
	char **params = splitFields(gccPart, &param_count);

	char **cmd = malloc(param_count * sizeof(char*));
	int cmd_count = 0;

	const char *skipParam[] = {"-o", "-Wdeclaration-after-statement"};
	int skipParamCount = 2;

	for (int i = 0; i < param_count; i++) {
		char *opt = params[i];
		char *eq_in_opt = strchr(opt, '=');
		if (eq_in_opt) {
			size_t len = eq_in_opt - opt;
			char *param = malloc(len + 1);
			memcpy(param, opt, len);
			param[len] = '\0';
			
			bool skip = false;
			for (int k = 0; k < skipParamCount; k++) {
				if (strcmp(param, skipParam[k]) == 0) {
					skip = true;
					break;
				}
			}
			free(param);
			if (!skip) {
				cmd[cmd_count++] = strdup(opt);
			}
		} else {
			bool skip = false;
			for (int k = 0; k < skipParamCount; k++) {
				if (strcmp(opt, skipParam[k]) == 0) {
					skip = true;
					break;
				}
			}
			if (!skip) {
				cmd[cmd_count++] = strdup(opt);
			} else {
				i++; // Skip next option value too
			}
		}
	}

	for (int i = 0; i < param_count; i++) {
		free(params[i]);
	}
	free(params);
	free(line);

	*out_cmd = cmd;
	*out_cmd_count = cmd_count;
	return 0;
}

static int cmdBuildFile(const char *srcFile, char ***out_cmd, int *out_cmd_count, char **out_extraCmd) {
	char *file = filenameNoExt(srcFile);
	char *dir = filepathDir(srcFile);
	
	char buf[PATH_MAX * 2];
	snprintf(buf, sizeof(buf), ".%s.o.cmd", file);
	char *dir_mod = filepathJoin(config.buildDir, dir);
	char *modFile = filepathJoin(dir_mod, buf);
	free(dir_mod);

	struct stat st;
	if (stat(modFile, &st) != 0) {
		free(file);
		free(dir);
		free(modFile);
		return -1;
	}

	char **cmd = NULL;
	int cmd_count = 0;
	char *extraCmd = NULL;
	if (cmdFromMod(modFile, &cmd, &cmd_count, &extraCmd) != 0) {
		free(file);
		free(dir);
		free(modFile);
		return -1;
	}
	free(modFile);

	int newCmd_cap = cmd_count + 10;
	char **newCmd = malloc(newCmd_cap * sizeof(char*));
	int newCmd_count = 0;

	newCmd[newCmd_count++] = strdup(cmd[0]);
	
	snprintf(buf, sizeof(buf), "-iquote %s%s", config.filesSrcDir, dir);
	newCmd[newCmd_count++] = strdup(buf);
	
	snprintf(buf, sizeof(buf), "-iquote %s%s", config.kernelSrcDir, dir);
	newCmd[newCmd_count++] = strdup(buf);

	for (int i = 1; i < cmd_count - 1; i++) {
		if (strncmp(cmd[i], "-I", 2) != 0) {
			if (newCmd_count >= newCmd_cap) {
				newCmd_cap *= 2;
				newCmd = realloc(newCmd, newCmd_cap * sizeof(char*));
			}
			newCmd[newCmd_count++] = strdup(cmd[i]);
		} else {
			char *inc = NULL;
			if (strcmp(cmd[i], "-I") == 0) {
				inc = strdup(cmd[i+1]);
				i++;
			} else {
				inc = strdup(cmd[i] + 2);
			}

			char *originInc = strdup(inc);
			
			char *old_inc = inc;
			if (inc[0] == '/') {
				size_t len_kernel = strlen(config.kernelSrcDir);
				if (strncmp(inc, config.kernelSrcDir, len_kernel) == 0) {
					char *rest = inc + len_kernel;
					char *new_inc = filepathJoin(config.filesSrcDir, rest);
					inc = new_inc;
					free(old_inc);
				}
			} else {
				char *new_inc = filepathJoin(config.filesSrcDir, inc);
				inc = new_inc;
				free(old_inc);
			}

			if (newCmd_count + 2 >= newCmd_cap) {
				newCmd_cap += 10;
				newCmd = realloc(newCmd, newCmd_cap * sizeof(char*));
			}

			if (fileExists(inc)) {
				snprintf(buf, sizeof(buf), "-I%s", inc);
				newCmd[newCmd_count++] = strdup(buf);
			}
			snprintf(buf, sizeof(buf), "-I%s", originInc);
			newCmd[newCmd_count++] = strdup(buf);

			free(inc);
			free(originInc);
		}
	}

	for (int i = 0; i < cmd_count; i++) {
		free(cmd[i]);
	}
	free(cmd);

	if (newCmd_count + 3 >= newCmd_cap) {
		newCmd_cap += 5;
		newCmd = realloc(newCmd, newCmd_cap * sizeof(char*));
	}
	
	snprintf(buf, sizeof(buf), "-I%s%s", config.filesSrcDir, dir);
	newCmd[newCmd_count++] = strdup(buf);
	
	snprintf(buf, sizeof(buf), "-I%s%s", config.linuxHeadersDir, dir);
	newCmd[newCmd_count++] = strdup(buf);
	
	snprintf(buf, sizeof(buf), "-I%s%s", config.kernelSrcDir, dir);
	newCmd[newCmd_count++] = strdup(buf);

	free(file);
	free(dir);

	*out_cmd = newCmd;
	*out_cmd_count = newCmd_count;
	*out_extraCmd = extraCmd;

	return 0;
}

static char **cmdPrefixMap(const char *from, const char *to, int *out_count) {
	char **res = malloc(3 * sizeof(char*));
	char buf[PATH_MAX * 2 + 50];
	snprintf(buf, sizeof(buf), "-fmacro-prefix-map=%s=%s", from, to);
	res[0] = strdup(buf);
	snprintf(buf, sizeof(buf), "-ffile-prefix-map=%s=%s", from, to);
	res[1] = strdup(buf);
	snprintf(buf, sizeof(buf), "-fdebug-prefix-map=%s=%s", from, to);
	res[2] = strdup(buf);
	*out_count = 3;
	return res;
}

int buildFile(const char *srcFile, const char *compileFile, const char *outFile) {
	char **cmd = NULL;
	int cmd_count = 0;
	char *extraCmd = NULL;

	if (cmdBuildFile(srcFile, &cmd, &cmd_count, &extraCmd) != 0) {
		LOG_ERR("Failed to get command to build %s", srcFile);
		free(extraCmd);
		return -1;
	}

	char currentPath[PATH_MAX];
	if (getcwd(currentPath, sizeof(currentPath)) == NULL) {
		LOG_ERR("Fail to fetch current directory");
		free(extraCmd);
		for (int i = 0; i < cmd_count; i++) free(cmd[i]);
		free(cmd);
		return -1;
	}

	char *r_outFile = NULL;
	if (outFile[0] != '/') {
		r_outFile = filepathJoin(currentPath, outFile);
	} else {
		r_outFile = strdup(outFile);
	}

	char *r_compileFile = NULL;
	if (compileFile[0] != '/') {
		r_compileFile = filepathJoin(currentPath, compileFile);
	} else {
		r_compileFile = strdup(compileFile);
	}

	// Append cmdPrefixMaps
	int expanded_cap = cmd_count + 30;
	char **expanded_cmd = malloc(expanded_cap * sizeof(char*));
	int expanded_count = 0;

	for (int i = 0; i < cmd_count; i++) {
		expanded_cmd[expanded_count++] = strdup(cmd[i]);
	}

	int pCount = 0;
	char *dirCompile = filepathDir(r_compileFile);
	char *dirSrc = filepathDir(srcFile);
	char **pMap = cmdPrefixMap(dirCompile, dirSrc, &pCount);
	free(dirSrc);
	free(dirCompile);
	for (int i = 0; i < pCount; i++) expanded_cmd[expanded_count++] = pMap[i];
	free(pMap);

	pMap = cmdPrefixMap(config.kernelSrcDir, "", &pCount);
	for (int i = 0; i < pCount; i++) expanded_cmd[expanded_count++] = pMap[i];
	free(pMap);

	char buf[PATH_MAX + 30];
	snprintf(buf, sizeof(buf), "%s./", config.kernelSrcDir);
	pMap = cmdPrefixMap(buf, "", &pCount);
	for (int i = 0; i < pCount; i++) expanded_cmd[expanded_count++] = pMap[i];
	free(pMap);

	pMap = cmdPrefixMap(config.filesSrcDir, "", &pCount);
	for (int i = 0; i < pCount; i++) expanded_cmd[expanded_count++] = pMap[i];
	free(pMap);

	snprintf(buf, sizeof(buf), "%s./", config.filesSrcDir);
	pMap = cmdPrefixMap(buf, "", &pCount);
	for (int i = 0; i < pCount; i++) expanded_cmd[expanded_count++] = pMap[i];
	free(pMap);

	pMap = cmdPrefixMap(config.linuxHeadersDir, "", &pCount);
	for (int i = 0; i < pCount; i++) expanded_cmd[expanded_count++] = pMap[i];
	free(pMap);

	snprintf(buf, sizeof(buf), "%s./", config.linuxHeadersDir);
	pMap = cmdPrefixMap(buf, "", &pCount);
	for (int i = 0; i < pCount; i++) expanded_cmd[expanded_count++] = pMap[i];
	free(pMap);

	expanded_cmd[expanded_count++] = strdup("-o");
	expanded_cmd[expanded_count++] = strdup(r_outFile);
	expanded_cmd[expanded_count++] = strdup(r_compileFile);

	// Construct command string to run via bash
	size_t cmd_len = 0;
	for (int i = 0; i < expanded_count; i++) {
		cmd_len += strlen(expanded_cmd[i]) + 1;
	}
	char *cmd_str = malloc(cmd_len + 1);
	cmd_str[0] = '\0';
	for (int i = 0; i < expanded_count; i++) {
		strcat(cmd_str, expanded_cmd[i]);
		if (i < expanded_count - 1) {
			strcat(cmd_str, " ");
		}
	}

	const char *working_dir = config.linuxHeadersDir;
	if (config.isModule) {
		char *check_path = findPathForFileFromCmdFile(config.buildDir, "arch/x86/include/generated/uapi/asm/types.h");
		if (check_path && strlen(check_path) > 0) {
			working_dir = config.buildDir;
		}
		free(check_path);
	}

	pid_t pid = fork();
	int build_failed = 0;
	if (pid == 0) {
		if (chdir(working_dir) != 0) {
			perror("chdir");
			exit(1);
		}
		char *args[] = {"bash", "-c", cmd_str, NULL};
		execvp("bash", args);
		perror("execvp");
		exit(1);
	} else if (pid > 0) {
		int status;
		waitpid(pid, &status, 0);
		if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
			LOG_ERR("Failed to build %s", srcFile);
			build_failed = 1;
		}
	} else {
		perror("fork");
		build_failed = 1;
	}

	free(cmd_str);
	for (int i = 0; i < expanded_count; i++) {
		free(expanded_cmd[i]);
	}
	free(expanded_cmd);
	for (int i = 0; i < cmd_count; i++) {
		free(cmd[i]);
	}
	free(cmd);

	if (build_failed) {
		free(r_compileFile);
		free(r_outFile);
		free(extraCmd);
		return -1;
	}

	// run extraObjtool/extraCmd logic
	if (extraCmd && strlen(extraCmd) > 0) {
		size_t ext_len = strlen(extraCmd);
		bool has_prefix = (strncmp(extraCmd, "./tools/objtool/objtool", 23) == 0);
		bool has_suffix = (ext_len >= 2 && strcmp(extraCmd + ext_len - 2, ".o") == 0);
		
		if (has_prefix && has_suffix) {
			int extra_count = 0;
			char **extra_fields = splitFields(extraCmd, &extra_count);
			
			char **newExtraCmd = malloc((extra_count + 1) * sizeof(char*));
			for (int i = 0; i < extra_count - 1; i++) {
				newExtraCmd[i] = strdup(extra_fields[i]);
			}
			newExtraCmd[extra_count - 1] = strdup(r_outFile);
			newExtraCmd[extra_count] = NULL;
			
			if (ShowDebugLog) {
				printf("Run extra command to build file:");
				for (int i = 0; i < extra_count; i++) {
					printf(" %s", newExtraCmd[i]);
				}
				printf("\n");
			}
			
			pid_t pid_extra = fork();
			if (pid_extra == 0) {
				if (chdir(config.buildDir) != 0) {
					perror("chdir");
					exit(1);
				}
				execvp(newExtraCmd[0], newExtraCmd);
				perror("execvp extra command");
				exit(1);
			} else if (pid_extra > 0) {
				int status_extra;
				waitpid(pid_extra, &status_extra, 0);
				if (!WIFEXITED(status_extra) || WEXITSTATUS(status_extra) != 0) {
					LOG_INFO("Failed to perform additional action for %s", srcFile);
				}
			}
			
			for (int i = 0; i < extra_count; i++) {
				free(newExtraCmd[i]);
			}
			free(newExtraCmd);
			
			for (int i = 0; i < extra_count; i++) {
				free(extra_fields[i]);
			}
			free(extra_fields);
		} else {
			LOG_INFO("Can't parse additional command to build file (%s)", extraCmd);
		}
	}

	free(r_compileFile);
	free(r_outFile);
	free(extraCmd);
	return 0;
}

static void remove_temp_obj_files(const char *dirpath) {
	DIR *dir = opendir(dirpath);
	if (!dir) return;
	struct dirent *entry;
	while ((entry = readdir(dir)) != NULL) {
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
			continue;
		char *fullpath = filepathJoin(dirpath, entry->d_name);
		struct stat st;
		if (lstat(fullpath, &st) == 0) {
			if (S_ISDIR(st.st_mode)) {
				remove_temp_obj_files(fullpath);
			} else {
				size_t len = strlen(entry->d_name);
				if ((len >= 3 && entry->d_name[0] == '_' && strcmp(entry->d_name + len - 2, ".o") == 0) ||
					strcmp(entry->d_name, "_*.o") == 0) {
					unlink(fullpath);
				}
			}
		}
		free(fullpath);
	}
	closedir(dir);
}

int buildModules(const char *moduleDir) {
	char *args[10];
	int arg_idx = 0;
	args[arg_idx++] = "make";
	char cross_compile_arg[PATH_MAX];
	if (config.isAARCH64) {
		args[arg_idx++] = "ARCH=arm64";
		snprintf(cross_compile_arg, sizeof(cross_compile_arg), "CROSS_COMPILE=%s", TOOLCHAIN);
		args[arg_idx++] = cross_compile_arg;
	}
	if (config.useLLVM && config.useLLVM[0] != '\0') {
		args[arg_idx++] = config.useLLVM;
	}
	args[arg_idx] = NULL;

	int pipefd[2];
	if (pipe(pipefd) < 0) {
		LOG_ERR("Failed to create pipe for module build");
		return -1;
	}

	pid_t pid = fork();
	if (pid < 0) {
		perror("fork");
		close(pipefd[0]);
		close(pipefd[1]);
		return -1;
	}

	if (pid == 0) {
		close(pipefd[0]);
		if (dup2(pipefd[1], STDOUT_FILENO) < 0 || dup2(pipefd[1], STDERR_FILENO) < 0) {
			perror("dup2");
			_exit(1);
		}
		close(pipefd[1]);
		if (chdir(moduleDir) != 0) {
			perror("chdir");
			_exit(1);
		}
		execvp(args[0], args);
		perror("execvp");
		_exit(1);
	}

	close(pipefd[1]);

	size_t cap = 4096;
	size_t len = 0;
	char *out = malloc(cap);
	if (out) {
		ssize_t n;
		while ((n = read(pipefd[0], out + len, cap - len - 1)) > 0) {
			len += n;
			if (cap - len < 1024) {
				cap *= 2;
				char *tmp = realloc(out, cap);
				if (!tmp) {
					LOG_ERR("Failed to reallocate memory for make output");
					break;
				}
				out = tmp;
			}
		}
		out[len] = '\0';
	}
	close(pipefd[0]);

	int status = 0;
	waitpid(pid, &status, 0);

	int build_failed = 0;
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		build_failed = 1;
	}

	char *logPath = filepathJoin(moduleDir, "build.log");
	FILE *fileLog = fopen(logPath, "w");
	if (!fileLog) {
		LOG_ERR("Failed to create logs file: %s", logPath);
	} else {
		if (out && len > 0) {
			fwrite(out, 1, len, fileLog);
		}
		fclose(fileLog);
	}
	free(logPath);

	if (build_failed) {
		bool errorCaught = false;
		if (out && len > 0) {
			const char *regexErr = "^.*(/[^/:]+\\.[^/:]+):([0-9]+):[0-9]+:.* error: (.+)$";
			regex_t regex;
			if (regcomp(&regex, regexErr, REG_EXTENDED | REG_NEWLINE) == 0) {
				char *copy = strdup(out);
				if (copy) {
					char *line = copy;
					char *next = NULL;
					while (line && *line != '\0') {
						next = strchr(line, '\n');
						if (next) {
							*next = '\0';
							if (next > line && *(next - 1) == '\r') {
								*(next - 1) = '\0';
							}
						}
						regmatch_t matches[4];
						if (regexec(&regex, line, 4, matches, 0) == 0) {
							char *file = strndup(line + matches[1].rm_so, matches[1].rm_eo - matches[1].rm_so);
							char *no_str = strndup(line + matches[2].rm_so, matches[2].rm_eo - matches[2].rm_so);
							char *err_str = strndup(line + matches[3].rm_so, matches[3].rm_eo - matches[3].rm_so);
							int no = atoi(no_str);

							errorCaught = true;
							LOG_INFO("%s:%d %serror:%s %s. See more: %s", file, no, RED, NC, err_str, "fileLog");

							free(file);
							free(no_str);
							free(err_str);
							break;
						}
						line = (next ? next + 1 : NULL);
					}
					free(copy);
				}
				regfree(&regex);
			}
		}

		if (!errorCaught) {
			printf("Error:\n");
			if (out && len > 0) {
				printf("%s", out);
				if (out[len - 1] != '\n') {
					printf("\n");
				}
			}
		}

		remove_temp_obj_files(moduleDir);
		free(out);
		return -1;
	}

	free(out);
	return 0;
}

int buildLivepatchModule(const char *moduleDir) {
	char *fileLog = filepathJoin(moduleDir, "build.log");
	char *oldFileLog = filepathJoin(moduleDir, "build_modules.log");
	rename(fileLog, oldFileLog);
	free(fileLog);
	free(oldFileLog);
	return buildModules(moduleDir);
}
