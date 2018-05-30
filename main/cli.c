/*
 * Locust - The Network security framework
 *
 * Copyright (C) 2009  Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

/*!
 * \file
 * \brief Locust command line interface.
 * \author Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 */

#include "locust.h"

#include <locust/logger.h>
#include <locust/string.h>
#include <locust/cli.h>

#define MAX_COMPLETE_MATCHES 80

/*!
 * \internal
 * \brief List with all the registered cli commands.
 */
static list_t registered_cli_commands;

/*!
 * \internal
 * \brief Lock mechanism to access the list of cli commands registered.
 * \see registered_cli_commands
 */
static struct lct_lock registered_cli_commands_lock;

#ifdef HAVE_LIBEDIT
/*! \brief libedit line structure. */
static EditLine *el;
/*! \brief libedit history structure. */
static History *hist;
/*! \brief Locust console prompt. */
static char console_prompt[128];
#endif

static int console_log_level;

#define LOCUST_HISTORY_FILENAME ".locust_history"
#define SCREEN_WIDTH 80

/*!
 * \internal
 * \brief This function is for internal use of the linked list implementation.
 */
static size_t list_registered_cli_commands_meter(const void *notused)
{
	return sizeof(struct lct_cli_command *);
}

/*!
 * \internal
 * \brief This function is for internal use of the linked list implementation.
 */
static int list_registered_cli_commands_comparator(const void *a, const void *b)
{
	return strcmp(((struct lct_cli_command *)a)->completecmd, ((struct lct_cli_command *)b)->completecmd);
}

/*!
 * \internal
 * \brief This function is for internal use of the linked list implementation.
 */
static int list_registered_cli_commands_seeker(const void *a, const void *key)
{
	return !strncmp(((struct lct_cli_command *)a)->completecmd, (const char *)key, strlen((const char *)key));
}

void lct_cli_set_loglevel(int level)
{
	console_log_level = level;
}

int lct_cli_get_loglevel(void)
{
	return console_log_level;
}

void lct_cli_output(char *fmt, ...)
{
	char *output;
	va_list ap;

	va_start(ap, fmt);
	vasprintf(&output, fmt, ap);
	va_end(ap);

	if (output) {
		/* print to the standard output. */
		printf ("%s", output);
		free(output);
	}
}

/*!
 * \internal
 * \brief Release cli command structure allocated memory.
 * \param cmd The command structure to free.
 * \retval < 0 on error (bogus command structure).
 * \retval 0 on success.
 */
static int free_cli_command(struct lct_cli_command *cmd)
{
	int i;

	if (!cmd || !cmd->completecmd || !cmd->summary) {
		lct_log(LCT_WARNING, "Trying to free a NULL cli command\n");
		return -1;
	}
	
	for (i = 0; i < cmd->args; i++) {
		free(cmd->cmd[i]);
	}

	free(cmd->completecmd);
	free(cmd->summary);
	free(cmd->syntax);
	free(cmd);

	return 0;
}

int lct_cli_command_register(const char *name, const char *summary, const char *syntax,
		enum lct_cli_result (*func)(struct lct_cliargs *cliargs), char *(*complete)(const char **cmd, const char *word, int pos, int state))
{
	struct lct_cli_command *cmd;
	char *cmdarg, *cmdcomplete;
	int args = 0, i;

	/* all the parameters are mandatory. */
	if (!name || !summary || !syntax || !func) {
		lct_log(LCT_ERROR, "Invalid call, all parameters are needed\n");
		return -1;
	}

	/* allocate the memory for the cli command structure. */
	cmd = calloc(1, sizeof(*cmd));
	if (!cmd) {
		lct_log(LCT_ERROR, "Unable to allocate cli_command structure\n");
		return -1;
	}

	/* populate the allocated structure. */
	cmdcomplete = lct_strdupa(name);
	if (!cmdcomplete) {
		lct_log(LCT_ERROR, "Unable to allocate memory\n");
		free(cmd);
		return -1;
	}
	while ((cmdarg = (char *)strsep(&cmdcomplete, " ")) && args < LCT_MAX_CMD_LEN) {
		cmd->cmd[args] = strdup(cmdarg);
		if (!cmd->cmd[args]) {
			for (i = 0; i < args; i++) {
				free(cmd->cmd[i]);
			}
			free(cmd);
			return -1;
		}
		args++;
	}

	cmd->completecmd = strdup(name);
	if (!cmd->completecmd) {
		for (i = 0; i < args; i++) {
			free(cmd->cmd[i]);
		}
		free(cmd);
		return -1;
	}
	cmd->func = func;
	cmd->complete = complete;
	cmd->summary = strdup(summary);
	lct_mutex_init(&cmd->lock, NULL);
	if (!cmd->summary) {
		for (i = 0; i < args; i++) {
			free(cmd->cmd[i]);
		}
		free(cmd->completecmd);
		free(cmd);
		return -1;
	}
	cmd->syntax = strdup(syntax);
	if (!cmd->syntax) {
		for (i = 0; i < args; i++) {
			free(cmd->cmd[i]);
		}
		free(cmd->completecmd);
		free(cmd->summary);
		free(cmd);
		return -1;
	}
	cmd->args = args;

	lct_mutex_lock(&registered_cli_commands_lock);
	/* insert the new command in the registered_cli_commands list. */
	list_append(&registered_cli_commands, cmd);
	/* sort the cli commands */
	list_sort(&registered_cli_commands, -1);
	lct_mutex_unlock(&registered_cli_commands_lock);

	return 0;
}

int lct_cli_command_unregister(const char *cmd)
{
	struct lct_cli_command *tmp;
	int pos;

	if (!cmd) {
		return -1;
	}

	lct_mutex_lock(&registered_cli_commands_lock);
	tmp = list_seek(&registered_cli_commands, cmd);
	if (!tmp) {
		lct_log(LCT_WARNING, "Command '%s' does not exist, unable to unregister it\n", cmd);
		lct_mutex_unlock(&registered_cli_commands_lock);
		return 0;
	}
	if (tmp->usecount) {
		lct_log(LCT_WARNING, "Command %s is being used (%d)\n", tmp->completecmd, tmp->usecount);
		lct_mutex_unlock(&registered_cli_commands_lock);
		return -1;
	}
	pos = list_locate(&registered_cli_commands, tmp);
	tmp = list_extract_at(&registered_cli_commands, pos);
	lct_mutex_unlock(&registered_cli_commands_lock);

	free_cli_command(tmp);
	lct_log(LCT_DEBUG, "CLI command '%s' unregistered\n", cmd);

	return 0;
}

/*!
 * \internal
 * \brief Find a command structure based on the command name.
 * \param name The command name.
 * \retval NULL If no command found by that name (or a memory allocation error).
 * \retval The command structure **LOCKED**.
 */
static struct lct_cli_command *find_command_locked(char *name)
{
	struct lct_cli_command *tmp, *res = NULL;
	int matchlen = 0, args = 0, i;
	char *namedup, *namearg;
	char *cmd[LCT_MAX_CMD_LEN];

	namedup = lct_strdupa(name);
	if (!namedup) {
		return NULL;
	}

	while ((namearg = (char *)strsep(&namedup, " ")) && args < LCT_MAX_CMD_LEN)  {
		if (strlen(namearg) > 0) {
			cmd[args] = namearg;
			args++;
		}
	}

	lct_mutex_lock(&registered_cli_commands_lock);
	list_iterator_start(&registered_cli_commands);
	while (list_iterator_hasnext(&registered_cli_commands)) {
		tmp = list_iterator_next(&registered_cli_commands);
		lct_mutex_lock(&tmp->lock);
		if (tmp->args <= args) {
			for (i = 0; i < args && i < tmp->args; i++) {
				if (strcasecmp(tmp->cmd[i], cmd[i])) {
					break;
				}
			}
			if (i >= matchlen && i == tmp->args) {
				if (res) {
					lct_mutex_unlock(&res->lock);
				}
				matchlen = i;
				res = tmp;
				continue;
			}
		}
		lct_mutex_unlock(&tmp->lock);
	}
	list_iterator_stop(&registered_cli_commands);
	lct_mutex_unlock(&registered_cli_commands_lock);

	return res;
}

char *lct_cli_command_complete(const char **options, const char *word, int state)
{
	char *ret = NULL;
	int i, found = 0;
	size_t wordlen = strlen(word);

	for (i = 0; options[i]; i++) {
		if (!strncasecmp(options[i], word, wordlen)) {
			if (found >= state) {
				ret = strdup(options[i]);
				break;
			}
			found++;
		}
	}

	return ret;
}

void lct_cli_join_args(char *dst, size_t len, char * const w[])
{
	const char *src;
	int i, offset = 0;

	if (!dst || !w) {
		return;
	}

	for (i = 0; offset < len && w[i]; i++) {
		if (i > 0) {
			dst[offset++] = ' ';
		}
		for (src = w[i]; *src && offset < len; src++) {
			dst[offset++] = *src;
		}
	}
	if (offset == len) {
		offset--;
	}
	dst[offset] = '\0';
}

/*!
 * \internal
 * \brief Handle CLI command 'repeat'
 * \param args The command arguments.
 */
static enum lct_cli_result handle_command_repeat(struct lct_cliargs *args)
{
	char repeatcmd[LCT_MAX_COMPLETE_CMD];
	int ntimes, i, res = CLI_SUCCESS;

	if (args->argc < 3) {
		return CLI_USAGE;
	}

	ntimes = atoi(args->argv[1]);
	if (ntimes <= 0) {
		lct_cli_output("Invalid number of repetitions, must be greater than 0.\n");
		return CLI_FAILED;
	}

	/* join the command */
	lct_cli_join_args(repeatcmd, sizeof(repeatcmd), &args->argv[2]);

	for (i = 0; i < ntimes && res == CLI_SUCCESS; i++) {
		res = lct_cli_run_command(repeatcmd);
	}

	return res;
}

/*!
 * \internal
 * \brief Handle CLI command 'help'.
 * \param args The command arguments.
 */
static enum lct_cli_result handle_command_help(struct lct_cliargs *args)
{
	struct lct_cli_command *cmd;
	char fullcmd[LCT_MAX_COMPLETE_CMD];

	if (args->argc > 1) {
		lct_cli_join_args(fullcmd, sizeof(fullcmd), &args->argv[1]);

		/* check for hardcoded exit */
		if (!strcasecmp(fullcmd, "exit")) {
			lct_cli_output("%30.30s %s '%s'\n", "exit", "Exit locust", "exit");
			return CLI_SUCCESS;
		}

		cmd = find_command_locked(fullcmd);
		if (cmd) {
			lct_cli_output("Command: %s\nSyntax: %s\nSummary: %s\n", cmd->completecmd, cmd->syntax, cmd->summary);
			lct_mutex_unlock(&cmd->lock);
			return CLI_SUCCESS;
		} else {
			lct_cli_output("Command '%s' not found\n", fullcmd);
			return CLI_FAILED;
		}
	}

	lct_cli_output("%30.30s %s\n", "Command", "Summary");
	lct_cli_output("%30.30s %s\n", "-------", "-------");

	lct_mutex_lock(&registered_cli_commands_lock);
	list_iterator_start(&registered_cli_commands);
	while (list_iterator_hasnext(&registered_cli_commands)) {
		cmd = list_iterator_next(&registered_cli_commands);
		lct_cli_output("%30.30s %s\n", cmd->completecmd, cmd->summary);
	}
	list_iterator_stop(&registered_cli_commands);
	lct_mutex_unlock(&registered_cli_commands_lock);

	/* hardcoded exit command. */
	lct_cli_output("%30.30s %s\n", "exit", "Exit locust");

	return CLI_SUCCESS;
}

int lct_cli_register_builtin_commands(void)
{
	int res;

	res = lct_cli_command_register("help", "Show help about every CLI command", "help", handle_command_help, NULL);
	res |= lct_cli_command_register("repeat", "Repeat X times a command", "repeat <ntimes> <command>", handle_command_repeat, NULL);

	return res;
}

#ifdef HAVE_LIBEDIT
/*!
 * \internal
 * \brief The function that generates the CLI prompt.
 * \param el The libedit main structure.
 * \retval The CLI prompt.
 */
static char *prompt(EditLine *el)
{
	snprintf(console_prompt, sizeof(console_prompt), "locust(%s@%s)%s ", lct_local_username(), lct_local_hostname(), (lct_running_as_root() ? "#" : "$"));
	return console_prompt;
}
#endif

#ifdef HAVE_LIBEDIT
/*!
 * \internal
 * \todo Finish this function
 * \brief CLI command completion.
 * \param el The libedit main structure.
 * \param ch TODO
 * \retval CC_ERROR on error. 
 */
static unsigned char command_complete(EditLine *el, int ch)
{
	LineInfo *lf = (LineInfo *)el_line(el);
	char *retstr, *ptr, *text, *argv[LCT_MAX_CMD_LEN];
	char *match_list[MAX_COMPLETE_MATCHES];
	int max_equal, repeat, max_word = 0, matches = 0, i, p, c, len, argc = 0;
	int retval = CC_ERROR;
	size_t completecmd_len;
	struct lct_cli_command *tmp;
	char *complete_tmp, completecmd[LCT_MAX_COMPLETE_CMD];
	char tmpchar;

	tmpchar = *(char *)lf->cursor;
	*(char *)lf->cursor = '\0';
	ptr = (char *)lf->cursor;
	if (ptr) {
		while (ptr > lf->buffer) {
			if (isspace(*ptr)) {
				ptr++;
				break;
			}
			ptr--;
		}
	}

	len = lf->cursor - ptr;

	text = lct_strdupa(lf->buffer);
	if (!text) {
		return CC_ERROR;
	}

	while ((argv[argc] = (char *)strsep(&text, " ")) && argc < LCT_MAX_CMD_LEN) {
		if (strlen(argv[argc]) > 0) {
			argc++;
		}
	}
	/* this is to prevent a crash if one space is passed before trying to autocomplete
	 * in the command line, couldn't find a better solution, but this should be fixed
	 * in a better way. */
	if (!argc) {
		len = 0;
	}

	lct_cli_join_args(completecmd, sizeof(completecmd) - 2, argv);
	completecmd_len = strlen(completecmd);
	if (!len && argc > 0) {
		/* put the last space in this command */
		completecmd[completecmd_len] = ' ';
		completecmd[completecmd_len + 1] = '\0';
		completecmd_len = strlen(completecmd);
		argv[argc] = " ";
	}

	lct_mutex_lock(&registered_cli_commands_lock);
	list_iterator_start(&registered_cli_commands);
	while (list_iterator_hasnext(&registered_cli_commands) && matches < MAX_COMPLETE_MATCHES) {
		tmp = list_iterator_next(&registered_cli_commands);
		lct_mutex_lock(&tmp->lock);
		if (!strncasecmp(tmp->completecmd, completecmd, completecmd_len)) {
			/* check for duplicates */
			p = argc;
			if (len) {
				p = argc - 1;
			}

			repeat = 0;
			if (p < tmp->args) {
				for (c = 1; c <= matches; c++) {
					if (!strcasecmp(match_list[c], tmp->cmd[p])) {
						repeat = 1;
						break;
					}
				}
				if (!repeat) {
					matches++;
					match_list[matches] = lct_strdupa(tmp->cmd[p]);
					if (!match_list[matches]) {
						return CC_ERROR;
					}
					if (strlen(tmp->cmd[p]) > max_word) {
						max_word = strlen(tmp->cmd[p]);
					}
				}
			}
		} else if (tmp->complete && !strncasecmp(tmp->completecmd, completecmd, strlen(tmp->completecmd))) {
			i = 0;
			while ((complete_tmp = tmp->complete((const char **)argv, (len ? argv[argc - 1] : ""), (len ? argc : argc + 1), i)) != NULL) {
				i++;
				repeat = 0;
				for (c = 1; c <= matches; c++) {
					if (!strcasecmp(match_list[c], complete_tmp)) {
						repeat = 1;
						break;
					}
				}
				if (!repeat) {
					matches++;
					match_list[matches] = lct_strdupa(complete_tmp);
					if (!match_list[matches]) {
						return CC_ERROR;
					}
					if (strlen(complete_tmp) > max_word) {
						max_word = strlen(complete_tmp);
					}
				}
				free(complete_tmp);
			}
		}
		lct_mutex_unlock(&tmp->lock);
	}
	list_iterator_stop(&registered_cli_commands);
	lct_mutex_unlock(&registered_cli_commands_lock);

	if (matches) {
		max_equal = strlen(match_list[1]);
		for (c = 2; c <= matches; c++) {
			for (i = 0; i < max_equal && tolower(match_list[1][i]) == tolower(match_list[c][i]); i++) {
				continue;
			}
			max_equal = i;
		}

		if (!(retstr = calloc(1, max_equal + 1))) {
			return CC_ERROR;
		}

		strncpy(retstr, match_list[1], max_equal);
		match_list[0] = retstr;
		el_deletestr(el, len);
		el_insertstr(el, match_list[0]);
		retval = CC_REFRESH;

		if (matches > 1) {
			int cols, near = 0;
			/* more than one match */
			cols = SCREEN_WIDTH / (max_word + 2);
			printf("\n");
			for (i = 1; i <= matches; i++) {
				printf("%-*s  ", max_word, match_list[i]);
				near = 0;
				if (!(i % cols)) {
					printf("\n");
					near = 1;
				}
			}
			if (!near) {
				printf ("\n");
			}
			retval = CC_REDISPLAY;
		} else {
			el_insertstr(el, " ");
		}
		free(match_list[0]);
	}

	*(char *)lf->cursor = tmpchar;

	return retval;
}
#endif

enum lct_cli_result lct_cli_run_command(const char *line)
{
	struct lct_cli_command *runcmd;
	char *argv[LCT_MAX_CMD_LEN], *cmd;
	int argc = 0;
	struct lct_cliargs *cmdargs;
	enum lct_cli_result cmdres = CLI_FAILED;

	cmd = lct_strdupa(line);
	if (!cmd) {
		return __CLI_NOTFOUND;
	}

	runcmd = find_command_locked(cmd);
	if (!runcmd) {
		return __CLI_NOTFOUND;
	}
	runcmd->usecount++;
	lct_mutex_unlock(&runcmd->lock);

	while ((argv[argc] = (char *)strsep(&cmd, " ")) && argc < LCT_MAX_CMD_LEN) {
		/* avoid putting empty strings inside argv when more than on
		 * space is inserted between the command words. */
		if (strlen(argv[argc]) > 0) {
			argc++;
		}
	}
	cmdargs = calloc(1, sizeof(*cmdargs));
	if (!cmdargs) {
		lct_log(LCT_ERROR, "Unable to allocate structure to pass parameter to function executed\n");
	} else {
		/* increment command usecount */
		cmdargs->argv = argv;
		cmdargs->argc = argc;
		cmdres = runcmd->func(cmdargs);
		free(cmdargs);
	}
	lct_mutex_lock(&runcmd->lock);
	runcmd->usecount--;
	lct_mutex_unlock(&runcmd->lock);

	return cmdres;
}

/*!
 * \brief The thread that shows the CLI console.
 * \param arg No parameters are being passed to the thread.
 * \retval No return value.
 */
void *lct_cli_console(void *arg)
{
#ifdef HAVE_LIBEDIT
	HistEvent ev;
	char *cmd;
	int count;
	enum lct_cli_result cmdres;
	struct lct_cli_command *command;
	char *onecmd;

	hist = history_init();
	if (!hist) {
		lct_thread_exit(THREAD_USER, NULL);
	}
	/* Remember 100 events in the history */
	history(hist, &ev, H_SETSIZE, 100);

	/* Initialize editline */
	el = el_init("locust", stdin, stdout, stderr);
	if (!el) {
		lct_thread_exit(THREAD_USER, NULL);
	}

	el_set(el, EL_EDITOR, "emacs");
	el_set(el, EL_EDITMODE, 1);
	el_set(el, EL_PROMPT, prompt);

	el_set(el, EL_HIST, history, hist);
	el_set(el, EL_ADDFN, "ed-complete", "Complete argument", command_complete);
	el_set(el, EL_BIND, "^I", "ed-complete", NULL);
	el_set(el, EL_BIND, "^D", "ed-redisplay", NULL);

	el_source(el, NULL);

	/* load the history from the file. */
	history(hist, &ev, H_LOAD, LOCUST_HISTORY_FILENAME);

	for (;;) {
		/* read a command. */
		cmd = (char *)el_gets(el, &count);
		if (count <= 1) {
			continue;
		}

		cmd[count - 1] = '\0';
		cmd = lct_stripwhite(cmd);

		/* check if the user is trying to exit the console. */
		if (!strcasecmp(cmd, "exit")) {
			lct_cli_output("Bye!\n");
			break;
		}

		while ((onecmd = strsep(&cmd, ";"))) {
			cmdres = lct_cli_run_command(onecmd);
			history(hist, &ev, H_ENTER, onecmd);
			switch (cmdres) {
				case CLI_SUCCESS:
					break;
				case CLI_FAILED:
					lct_cli_output("Command '%s' failed\n", onecmd);
					break;
				case CLI_USAGE:
					command = find_command_locked(onecmd);
					if (command) {
						lct_cli_output("Usage:\n%s\n", command->syntax);
						lct_mutex_unlock(&command->lock);
					}
					break;
				case __CLI_NOTFOUND:
					lct_cli_output("No such command '%s'\n", onecmd);
					break;
			}
		}
	}

	/* save the history */
	history(hist, &ev, H_SAVE, LOCUST_HISTORY_FILENAME);
	history_end(hist);
	el_end(el);
#endif

	lct_thread_exit(THREAD_USER, NULL);
	return NULL;
}

/*! \brief Simple stdout logger backend. */
static void  __attribute__ ((format(printf, 5, 0))) stdout_logger(const char *file, int line, const char *fun, int level, char *fmt, va_list ap)
{
	char *str;

	if  (console_log_level < 0) {
		return;
	}

	if (level <= console_log_level) {
		if (vasprintf(&str, fmt, ap) < 0) {
			return;
		}
		printf("#%s# [%s]-(%d:%s) %s\n", lct_logger_level2str(level), file, line, fun, str);
		free(str);
	}
}

int lct_cli_finish(void)
{
	int ret;

	ret = lct_cli_command_unregister("help");
	ret |= lct_cli_command_unregister("repeat");

	list_destroy(&registered_cli_commands);
	lct_mutex_destroy(&registered_cli_commands_lock);

	ret |= lct_logger_unregister("stdout");

	return ret;
}

int lct_cli_initialize(void)
{
	list_init(&registered_cli_commands);
	list_attributes_copy(&registered_cli_commands, list_registered_cli_commands_meter, 0);
	list_attributes_comparator(&registered_cli_commands, list_registered_cli_commands_comparator);
	list_attributes_seeker(&registered_cli_commands, list_registered_cli_commands_seeker);

	lct_mutex_init(&registered_cli_commands_lock, NULL);

	console_log_level = 0; 

	if (lct_logger_register("stdout", stdout_logger) < 0) {
		return -1;
	}
	return 0;
}

