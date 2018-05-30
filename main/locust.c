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
 * \mainpage Locust - The Network security framework.
 *
 * \par Developer documentation for Locust.
 * The network security framework
 */

/*! 
 * \file
 * \brief The main Locust module.
 * \author Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 */

#include "locust.h"

#include <locust/_private.h>
#include <locust/config.h>
#include <locust/loader.h>
#include <locust/version.h>
#include <locust/logger.h>
#include <locust/cli.h>

#include <sys/resource.h>

#define DEFAULT_MAX_OPEN_FILES 1500

/*! \brief The Console main thread. */
static pthread_t cli_console_thread;

/*! \brief Is locust running as root? */
static int is_root;
/*! \brief The machine hostname */
static char locust_hostname[128];
/*! \brief Username */
static struct passwd *locust_pw;

char *lct_local_hostname(void)
{
	return locust_hostname;
}

int lct_running_as_root(void)
{
	return is_root;
}

char *lct_local_username(void)
{
	return (char *)locust_pw->pw_name;
}

/*! \brief Handle CLI command 'version'. */
static enum lct_cli_result handle_command_version(struct lct_cliargs *args)
{
	lct_cli_output("Locust version %s\n", lct_get_version());
	return CLI_SUCCESS;
}

/*!
 * \brief Print the Locust usage information to stdout.
 * \param cmdname The binary name.
 */
static void locust_usage(char *cmdname)
{
	printf ("Locust %s Copyright (C) 2009 Eliel C. Sardanons <eliels@gmail.com>\n", lct_get_version());
	printf ("Usage: %s [OPTIONS]\n", cmdname);
	printf ("    -c <configfile>  Load 'locust.conf' from another path.\n");
	printf ("    -e <command>     Run a CLI command and exit.\n");
	printf ("    -h               Show this help menu.\n");
	printf ("    -v               Show Locust version and exit.\n");
	printf ("    -l <level>       Set the console logging level (< 0 disable the console logging).\n");
	printf ("\n");
}

int main (int argc, char *argv[])
{
	int maxfiles, res, c, runcmd = 0, level;
	enum lct_cli_result cmdres = CLI_SUCCESS;
	char *arg = NULL, *onecmd;
	/* did we loaded the configuration file? */
	int config_loaded = 0;
	struct rlimit rl;

	/* initialize the logger subsystem */
	if (lct_logger_initialize() < 0) {
		printf ("Error initializing logger\n");
		return -1;
	}

	/* initialize the config subsystem. */
	if (lct_config_initialize() < 0) {
		lct_log(LCT_ERROR, "Error initializing the config subsystem\n");
		return -1;
	}

	/* initialize the cli subsystem. */
	if (lct_cli_initialize() < 0) {
		lct_log(LCT_ERROR, "Error initializing the cli subsystem\n");
		return -1;
	}

	/* initialize the routing subsystem. */ 
	if (lct_route_initialize() < 0) {
		return -1;
	}

	/* Get parameter options */
	while ((c = getopt(argc, argv, "c:e:hl:v")) != -1) {
		switch (c) {
			case 'c':
				/* load main configuration file */
				if (!lct_config_load(optarg)) {
					locust_usage(argv[0]);
					return -1;
				}
				config_loaded = 1;
				break;
			case 'e':
				arg = lct_strdupa(optarg);
				if (!arg) {
					return -1;
				}
				runcmd = 1;
				break;
			case 'h':
				/* show all the parameters and exit */
				locust_usage(argv[0]);
				return 0;
			case 'l':
				/* set the console logging level. */
				level = atoi(optarg);
				lct_cli_set_loglevel(level);
				break;
			case 'v':
				/* show version info and exit */
				printf ("Locust %s\n", lct_get_version());
				return 0;
			case '?':
			default:
				locust_usage(argv[0]);
				return -1;
		}
	}

	if (!config_loaded) {
		/* load main configuration file */
		if (!lct_config_load(LCT_MAIN_CONFIG_FILE)) {
			locust_usage(argv[0]);
			return -1;
		}
	}

	/* Is locust running as root? */
	if (geteuid() == 0) {
		is_root = 1;
	} else {
		is_root = 0;
	}

	maxfiles = lct_config_int(LCT_CONFIG_MAX_OPEN_FILES);
	if (maxfiles <= 0) {
		maxfiles = DEFAULT_MAX_OPEN_FILES;
	}

	rl.rlim_cur = maxfiles;
	rl.rlim_max = maxfiles;

	if (setrlimit(RLIMIT_NOFILE, &rl)) {
		lct_log(LCT_WARNING, "Unable to set the maximum number of open files to %d\n", maxfiles);
	}

	/* Get the hostname */
	if (gethostname(locust_hostname, sizeof(locust_hostname))) {
		/* We couldn't get the hostname (using 'localhost') */
		snprintf(locust_hostname, sizeof(locust_hostname), "localhost");
	}

	/* Get the username as we are running. */
	locust_pw = getpwuid(geteuid());

	/* initialize the thread subsystem */
	if (lct_thread_initialize() < 0) {
		lct_log(LCT_ERROR, "Error initializing the thread subsystem.\n");
		return -1;
	}

	/* initialize the host subsystem. */
	if (lct_host_initialize() < 0) {
		lct_log(LCT_ERROR, "Error initializing the host subsystem.\n");
		return -1;
	}


	/* initialize the scanner subsystem. */
	if (lct_scanners_initialize() < 0) {
		lct_log(LCT_ERROR, "Error initializing the scanner subsystem.\n");
		return -1;
	}

	/* initialize the wordlist subsystem. */
	if (lct_wordlist_initialize() < 0) {
		lct_log(LCT_ERROR, "Error initializing the wordlist subsystem.\n");
		return -1;
	}

	/* initialize the packet subsystem. */
	if (lct_packet_initialize() < 0) {
		lct_log(LCT_ERROR, "Error initializing the packet subsystem.\n");
		return -1;
	}

	/* initialize the sniffer subsystem. */
	if (lct_sniffer_initialize() < 0) {
		lct_log(LCT_ERROR, "Error initializing the sniffer subsystem\n");
		return -1;
	}

	/* initialize the loader subsystem. */
	if (lct_loader_initialize() < 0) {
		lct_log(LCT_ERROR, "Error initializing the loader subsystem.\n");
		return -1;
	}

	/* Register CLI command 'version' */
	lct_cli_command_register("version", "Show locust version", "version", handle_command_version, NULL);

	/* register builtin CLI/Injectors */
	lct_cli_register_builtin_commands();
	lct_host_register_builtin_commands();
	lct_tcp_register_builtin_commands();
	lct_udp_register_builtin_commands();
	lct_ip_register_builtin_commands();
	lct_ethernet_register_builtin_commands();
	lct_payload_register_builtin_commands();
	lct_icmp_register_builtin_commands();

	/* HERE WE FINISH LOADING THE CORE */

	/* the user is trying to execute commands passing the 'e' parameter. */
	if (runcmd) {
		while ((onecmd = strsep(&arg, ";"))) {
			/* Execute a command and exit */
			cmdres = lct_cli_run_command(onecmd);
			switch (cmdres) {
				case __CLI_NOTFOUND:
					printf ("No such command '%s'\n", onecmd);
					break;
				case CLI_FAILED:
					break;
				case CLI_SUCCESS:
					break;
				case CLI_USAGE:
					break;
			}
		}
		return cmdres;
	}

	/* print version information */
	lct_cli_output("Locust [%s]\nCreated by Eliel C. Sardanons <eliels@gmail.com>\n", lct_get_version());
	lct_cli_output("-{ Type 'help' for a list of available commands. }-\n\n");

	/* Setup the console */
	res = lct_thread(THREAD_USER, &cli_console_thread, lct_cli_console, NULL);
	if (res) {
		lct_log(LCT_ERROR, "Error initializing the console (%d)\n", res);
		return -1;
	}

	lct_thread_join(cli_console_thread, NULL);
	lct_cli_command_unregister("version");
	/* unload every loaded module. */
	lct_loader_finish();
	/* close the sniffer subsystem. */
	lct_sniffer_finish();
	/* close the host subsystem. */
	lct_host_finish();
	/* close the wordlist subsystem. */
	lct_wordlist_finish();
	/* close the tcp subsystem. */
	lct_tcp_finish();
	/* close the tcp subsystem. */
	lct_udp_finish();
	/* close the packet subsystem. */
	lct_packet_finish();
	/* close the cli subsystem. */
	lct_cli_finish();
	/* close the routing subsystem. */
	lct_route_finish();

	return 0;
}

