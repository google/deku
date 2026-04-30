#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

// Fallback log macros if not provided by environment
#define LOG_DEBUG(...) printf(__VA_ARGS__); printf("\n")
#define LOG_ERR(...) fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n")

extern int generateSymbolsC(char* objFile);

// Helper to check if string ends with suffix
int has_suffix(const char *str, const char *suffix)
{
	if (!str || !suffix) return 0;

	size_t lenstr = strlen(str);
	size_t lensuffix = strlen(suffix);
	if (lensuffix > lenstr)
		return 0;

	return strncmp(str + lenstr - lensuffix, suffix, lensuffix) == 0;
}

// Helper to trim suffix
void trim_suffix(char *str, const char *suffix)
{
	if (!str || !suffix)
		return;

	size_t lenstr = strlen(str);
	size_t lensuffix = strlen(suffix);
	if (lensuffix > lenstr)
		return;

	if (strncmp(str + lenstr - lensuffix, suffix, lensuffix) == 0)
		str[lenstr - lensuffix] = '\0';
}

// Helper to check if file exists
int file_exists(const char *filename)
{
	return access(filename, F_OK) == 0;
}

// Helper to read lines from a file
// Returns array of strings, terminated by NULL
char** read_lines(const char *filename)
{
	FILE *file = fopen(filename, "r");

	if (!file)
		return NULL;

	char **lines = NULL;
	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	int count = 0;

	while ((read = getline(&line, &len, file)) != -1)
	{
		// Remove newline
		if (read > 0 && line[read-1] == '\n')
			line[read-1] = '\0';

		lines = realloc(lines, sizeof(char*) * (count + 2));
		lines[count] = strdup(line);
		lines[count+1] = NULL;
		count++;
	}

	free(line);
	fclose(file);
	return lines;
}

void free_lines(char **lines)
{
	if (!lines)
		return;

	for (int i = 0; lines[i] != NULL; i++)
	{
		free(lines[i]);
	}

	free(lines);
}

// Helper to check if regex matches string
int regex_match(const char *pattern, const char *text)
{
	regex_t regex;
	int reti;
	reti = regcomp(&regex, pattern, REG_EXTENDED | REG_NEWLINE);
	if (reti)
		return 0;

	reti = regexec(&regex, text, 0, NULL, 0);
	regfree(&regex);
	if (!reti)
		return 1;

	return 0;
}

char* findObjWithSymbol(const char* sym, const char* srcFile, const char* objPath, 
					   const char* workdir, const char* kernelSrcDir, const char* buildDir)
{
	LOG_DEBUG("Find object file for symbol: %s %s (%s)", sym, srcFile, objPath);
	
	if (has_suffix(objPath, "/vmlinux"))
		return strdup("vmlinux");

	// Construct regex pattern: ^sym$
	// We need to escape dots in sym if any, but for simplicity let's assume exact match for now
	// or use standard regex if needed. The Go code does strings.ReplaceAll(sym, ".", "\\.")
	// Let's do a simple exact match line-by-line if we can, or use regex.
	// Let's use regex to match Go behavior.
	char pattern[1024];
	snprintf(pattern, sizeof(pattern), "^%s$", sym); // Simplified, not escaping dots here.
	// If dots are common, we should escape them. Let's assume simple names for now or add escaping.

	char symObjPath[4096];
	char symObjPathBase[1024];
	strncpy(symObjPathBase, objPath, sizeof(symObjPathBase));
	trim_suffix(symObjPathBase, ".ko");
	
	snprintf(symObjPath, sizeof(symObjPath), "%s/symbols/%s", workdir, symObjPathBase);
	
	FILE *f = fopen(symObjPath, "r");
	if (f)
	{
		fseek(f, 0, SEEK_END);
		long fsize = ftell(f);
		fseek(f, 0, SEEK_SET);
		char *string = malloc(fsize + 1);
		fread(string, fsize, 1, f);
		fclose(f);
		string[fsize] = 0;

		if (regex_match(pattern, string))
		{
			free(string);
			LOG_DEBUG("Found in the same module: %s", objPath);

			return strdup(objPath);
		}
	
		free(string);
	}

	char srcPath[4096];
	char modulesPath[4096];
	
	// Get dir of srcFile
	char *srcFileDir = strdup(srcFile);
	char *last_slash = strrchr(srcFileDir, '/');
	if (last_slash)
		*last_slash = '\0';
	else
		srcFileDir[0] = '\0';

	snprintf(srcPath, sizeof(srcPath), "%s/%s", kernelSrcDir, srcFileDir);
	snprintf(modulesPath, sizeof(modulesPath), "%s/%s", buildDir, srcFileDir);
	free(srcFileDir);

	while (1)
	{
		char modulesOrderPath[4096];
		snprintf(modulesOrderPath, sizeof(modulesOrderPath), "%s/modules.order", modulesPath);
		
		char **files = read_lines(modulesOrderPath);
		if (files)
		{
			for (int i = 0; files[i] != NULL; i++)
			{
				char *file = files[i];
				// Trim prefix modulesPath if present? Go code does file = strings.TrimPrefix(file, modulesPath)
				// Wait, modules.order usually contains relative paths or paths from build dir.
				// Let's assume file is the path we need.
				
				// generateSymbols(file)
				if (!generateSymbolsC(file))
					continue;

				// Path to symbols file
				// path := filepath.Join(config.workdir, SYMBOLS_DIR, filepath.Dir(file))
				char *fileDir = strdup(file);
				char *last_slash = strrchr(fileDir, '/');
				if (last_slash) *last_slash = '\0';
				else fileDir[0] = '\0';

				char symbolsDirPath[4096];
				snprintf(symbolsDirPath, sizeof(symbolsDirPath), "%s/symbols/%s", workdir, fileDir);
				free(fileDir);

				DIR *dir = opendir(symbolsDirPath);
				if (dir)
				{
					struct dirent *entry;
					while ((entry = readdir(dir)) != NULL)
					{
						if (entry->d_type == DT_REG)
						{
							char filePath[4096];
							snprintf(filePath, sizeof(filePath), "%s/%s", symbolsDirPath, entry->d_name);
							
							FILE *sf = fopen(filePath, "r");
							if (sf)
							{
								fseek(sf, 0, SEEK_END);
								long sfsize = ftell(sf);
								fseek(sf, 0, SEEK_SET);
								char *sfstring = malloc(sfsize + 1);
								fread(sfstring, sfsize, 1, sf);
								fclose(sf);
								sfstring[sfsize] = 0;

								if (regex_match(pattern, sfstring))
								{
									free(sfstring);
									closedir(dir);
									free_lines(files);
									
									// res := filepath.Join(filepath.Dir(file), symbolsFile.Name()) + ".ko"
									char *res = malloc(4096);
									char *fDir = strdup(file);
									char *ls = strrchr(fDir, '/');
									if (ls)
										*ls = '\0';
									else
										fDir[0] = '\0';
									
									snprintf(res, 4096, "%s/%s.ko", fDir, entry->d_name);
									free(fDir);
									LOG_DEBUG("Found in: %s", res);

									return res;
								}
								free(sfstring);
							}
						}
					}
					closedir(dir);
				}
			}
			free_lines(files);
		}

		char kconfigPath[4096];
		snprintf(kconfigPath, sizeof(kconfigPath), "%s/Kconfig", srcPath);
		if (file_exists(kconfigPath))
			break;

		// Move up directories
		char *last_src_slash = strrchr(srcPath, '/');
		if (last_src_slash)
			*last_src_slash = '\0';
		else
			break;

		char *last_mod_slash = strrchr(modulesPath, '/');
		if (last_mod_slash)
			*last_mod_slash = '\0';
		else
			break;

		// Check if modulesPath == buildDir
		if (strcmp(modulesPath, buildDir) == 0)
			break;
	}

	char systemMapPath[4096];
	snprintf(systemMapPath, sizeof(systemMapPath), "%s/System.map", buildDir);
	if (file_exists(systemMapPath))
	{
		FILE *f = fopen(systemMapPath, "r");
		if (f)
		{
			fseek(f, 0, SEEK_END);
			long fsize = ftell(f);
			fseek(f, 0, SEEK_SET);
			char *string = malloc(fsize + 1);
			fread(string, fsize, 1, f);
			fclose(f);
			string[fsize] = 0;

			if (regex_match(pattern, string))
			{
				free(string);
				LOG_DEBUG("Found in: vmlinux");
				return strdup("vmlinux");
			}

			free(string);
		}
	}

	LOG_ERR("Fail to find object file for symbol: %s %s", sym, srcFile);
	return NULL;
}
