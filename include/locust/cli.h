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
 * \brief Command line interface definitions.
 * \author Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 */

#ifndef LOCUST_CLI_H
#define LOCUST_CLI_H

#ifdef HAVE_LIBEDIT
#include "histedit.h"
#endif

#define LCT_MAX_CMD_LEN		20 
#define LCT_MAX_COMPLETE_CMD	256

/*! \brief CLI commands result. */
enum lct_cli_result {
	CLI_FAILED,		/*!< The command failed while running for some reason. */
	CLI_USAGE,		/*!< Show how to use the command. */
	CLI_SUCCESS,		/*!< The CLI command was executed succesfully */
	__CLI_NOTFOUND		/*!< for internal use only */
};

/*! \brief All the arguments passed to the CLI command. */
struct lct_cliargs {
	/*! \brief List of arguments. */
	char **argv;
	/*! \brief Number of arguments. */
	int argc;
};

/*!
 * \brief A CLI command in memory.
 */
struct lct_cli_command {
	/*! \brief Command separated in the array. */
	char *cmd[LCT_MAX_CMD_LEN];
	/*! \brief Complete command name */
	char *completecmd;
	/*! \brief Number of arguments */
	int args;
	/*! \brief Command syntax documentation */
	char *syntax;
	/*! \brief Command summary documentation */
	char *summary;
	/*! \brief Pointer of the command handler */
	enum lct_cli_result (*func)(struct lct_cliargs *cliargs);
	/*! \brief Command completion function. */
	char *(*complete)(const char **cmd, const char *word, int pos, int state);
	/*! \brief Command usecount */
	int usecount;
	/*! \brief Locking of this command while running to avoid someone
	 * unregistering it */
	struct lct_lock lock;
};

/*!
 * \brief Set the console logging level.
 * \param level The log level integer value.
 */
void lct_cli_set_loglevel(int level);

/*!
 * \brief Get the current logging level.
 */
int lct_cli_get_loglevel(void);

/*!
 * \brief Register a CLI command.
 * \param name Name of the command to register.
 * \param summary Documentation about the command.
 * \param syntax Documentation about the command.
 * \param func Function to handle the command being registered.
 * \param complete The autocomplete handler for the command being registered.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
int lct_cli_command_register(const char *name, const char *summary, const char *syntax,
		enum lct_cli_result (*func)(struct lct_cliargs *cliargs), char *(*complete)(const char **cmd, const char *word, int pos, int state));

/*!
 * \brief Unregister a CLI command.
 * \param cmd The command to unregister.
 * \retval < 0 on error.
 * \retval 0 on success.
 */
int lct_cli_command_unregister(const char *cmd);

/*!
 * \brief Output a message to the locust console.
 * \param fmt Format string.
 */
void lct_cli_output(char *fmt, ...) __attribute__((format(printf, 1, 2)));

/*!
 * \brief Run a cli command.
 * \param cmd command name.
 * \retval __CLI_NOTFOUND if the command is not found.
 * \retval CLI_SUCCESS if the command ran without problems.
 * \retval CLI_FAILED if the command failed to run.
 * \retval CLI_USAGE if there was a problem with the parameters being passed
 * to the command.
 */
enum lct_cli_result lct_cli_run_command(const char *cmd);

/*!
 * \brief Command autocomplete helper.
 * \param options The list of options NULL terminated.
 * \param word The word to autocomplete.
 * \param state The result number.
 * \retval NULL if no matching option.
 * \retval The option that matchs 'word'.
 */
char *lct_cli_command_complete(const char **options, const char *word, int state);

/*!
 * \brief Join the words inside an array in a single string space separated.
 * \param dst The destination pointer (already allocated memory).
 * \param len The maximum size of the dst buffer.
 * \param w The array with the words we want to join.
 */
void lct_cli_join_args(char *dst, size_t len, char * const w[]);

#endif /* LOCUST_CLI_H */
