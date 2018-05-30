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
 * \brief The Locust module loader.
 * \author Eliel C. Sardanons (LU1ALY) <eliels@gmail.com>
 */

#include "locust.h"

#include <locust/_private.h>
#include <locust/config.h>
#include <locust/logger.h>
#include <locust/cli.h>

#include <dlfcn.h>
#include <glob.h>

static const char *modules_path = "modules/";

#define MAX_MODULE_NAME 512

/*! \brief The module structure definition. */
struct lct_module {
	/*! Module name. */
	char *name;
	/*! Module filename. */
	char *filename;
	/*! Handler from dlopen() */
	void *handle;
	/*! Module load function pointer. */
	int (*load)(void);
	/*! Module unload function pointer. */
	int (*unload)(void);
	/*! Module refcount. */
	int refcount;
};

/*! \brief The list of loaded modules. */
static list_t modules;
/*! \brief Locking for the list of modules. */
static struct lct_lock modules_list_lock;

/*!
 * \internal
 * \brief This function is for internal use of the linked list implementation.
 */
static size_t list_modules_meter(const void *notused)
{
	return sizeof(struct lct_module *);
}

/*!
 * \internal
 * \brief This function is for internal use of the linked list implementation.
 */
static int list_modules_comparator(const void *a, const void *b)
{
        struct lct_module *m1 = (struct lct_module *)a;
        struct lct_module *m2 = (struct lct_module *)b;

        return strcmp(m1->name, m2->name);
}

/*!
 * \internal
 * \brief This function is for internal use of the linked list implementation.
 */
static int list_modules_seeker(const void *a, const void *key)
{
        struct lct_module *m = (struct lct_module *)a;
        const char *name = (const char *)key;

        return !strcmp(m->name, name);
}

/*!
 * \internal
 * \brief Lock the modules list.
 */
static void modules_lock(void)
{
	lct_mutex_lock(&modules_list_lock);
}

/*!
 * \internal
 * \brief Unlock the modules list.
 */
static void modules_unlock(void)
{
	lct_mutex_unlock(&modules_list_lock);
}

/*!
 * \internal
 * \brief Free a module structure.
 * \param mod The module structure to free.
 */
static void free_module(struct lct_module *mod)
{
	free(mod->name);
	free(mod->filename);
	free(mod);
}

/*!
 * \internal
 * \brief Open a module and load it in the list.
 * \param modulename The name of the module we want to open.
 * \retval The allocated module structure.
 * \retval NULL on error.
 */
static struct lct_module *module_open(const char *modulename)
{
	void *handle;
	char *modname;
	struct lct_module *mod;
	char filename[MAX_MODULE_NAME];

	/* Generate the full path to access the module filename. */
	snprintf(filename, sizeof(filename), "%s", modulename);

	/* Open the module. */
	handle = dlopen(filename, RTLD_LAZY);
	if (!handle) {
		lct_log(LCT_ERROR, "Couldn't load module: %s (%s)\n", filename, dlerror());
		return NULL;
	}

	/* Allocate the module structure. */
	mod = calloc(1, sizeof(*mod));
	if (!mod) {
		lct_log(LCT_ERROR, "Unable to allocate the module structure, can not load module '%s'\n", filename);
		dlclose(handle);
		return NULL;
	}

	/* check if module_load and module_unload are defined inside the module. */
	mod->load = dlsym(handle, "module_load");
	if (!mod->load) {
		lct_log(LCT_ERROR, "Module '%s' is not implementing the mandatory load function 'module_load'\n", modulename);
		dlclose(handle);
		free(mod);
		return NULL;
	}

	mod->unload = dlsym(handle, "module_unload");
	if (!mod->unload) {
		lct_log(LCT_ERROR, "Module '%s' is not implementing the mandatory load function 'module_unload'\n", modulename);
		dlclose(handle);
		free(mod);
		return NULL;
	}

	mod->filename = strdup(filename);
	/* Get the module name. */
	modname = strrchr(filename, '/');
	if (!modname) {
		modname = filename;
	}
	mod->name = strdup(modname + 1);
	mod->handle = handle;

	/* Insert the module in the modules list. */
	modules_lock();
	list_append(&modules, mod);
	modules_unlock();	

	return mod;
}

/*!
 * \internal
 * \brief Close an already open module.
 * \param module The module structure to close.
 * \retval 0 on success.
 * \retval < 0 on error.
 */
static int module_close(struct lct_module *module)
{
	struct lct_module *tmp;
	int pos;

	if (module->refcount > 0) {
		lct_log(LCT_ERROR, "Module is in use, we can't close it\n");
		return -1;
	}

	pos = list_locate(&modules, module);
	if (pos < 0) {
		lct_log(LCT_ERROR, "Internal error, unable to locate the module to close\n");
		return -1;
	}
	tmp = list_extract_at(&modules, pos);

	if (!tmp) {
		lct_log(LCT_ERROR, "Internal error, unable to extract the module to close\n");
		return -1;
	}	
	dlclose(tmp->handle);
	free_module(tmp);

	return 0;
}

int lct_module_load(const char *modulename)
{
	struct lct_module *mod;
	int err;

	mod = module_open(modulename);
	if (!mod) {
		return -1;
	}

	err = mod->load();
	if (err) {
		lct_log(LCT_ERROR, "Error loading module '%s'\n", mod->name);
		return err;
	}

	return 0;
}

int lct_module_unload(const char *name)
{
	int err;
	struct lct_module *mod;

	modules_lock();
	mod = list_seek(&modules, name);
	if (!mod) {
		modules_unlock();
		lct_log(LCT_DEBUG, "Couldnt find module '%s' for unloading\n", name);
		return -1;
	}

	err = mod->unload();
	if (err) {
		lct_log(LCT_ERROR, "Can't unload module '%s'\n", name);
		modules_unlock();
		return err;
	}
	module_close(mod);
	modules_unlock();

	return 0;
}

/*!
 * \brief CLI command 'module show' to show the loaded modules.
 */
static enum lct_cli_result handle_command_modules_show(struct lct_cliargs *args)
{
#define MODULE_SHOW_FORMAT_TITLE "%-20s\n"
#define MODULE_SHOW_FORMAT "%-20s\n"
	struct lct_module *mod;
	int modcount = 0;

	modules_lock();
	lct_cli_output(MODULE_SHOW_FORMAT_TITLE, "Module name");
	list_iterator_start(&modules);
	while (list_iterator_hasnext(&modules)) {
		mod = (struct lct_module *)list_iterator_next(&modules);
		lct_cli_output(MODULE_SHOW_FORMAT, mod->name);
		modcount++;
	}
	list_iterator_stop(&modules);
	modules_unlock();
	lct_cli_output("%d module%s loaded\n", modcount, (modcount == 1 ? "" : "s"));

	return CLI_SUCCESS;
#undef MODULE_SHOW_FORMAT_TITLE
#undef MODULE_SHOW_FORMAT
}

int lct_loader_finish(void)
{
	struct lct_module *mod;

	lct_cli_command_unregister("modules show");
	/* unload every loaded module. */
	modules_lock();
	while (list_size(&modules) > 0) {	
		mod = list_get_at(&modules, 0);
		lct_log(LCT_DEBUG, "Unloading module '%s'\n", mod->name);
		mod->unload();
		module_close(mod);
	}
	modules_unlock();
	list_destroy(&modules);
	lct_mutex_destroy(&modules_list_lock);

	return 0;
}

int lct_loader_initialize(void)
{
	const char *modpath;
	char *modspattern;
	int globret, i;
	glob_t globbuf;

	list_init(&modules);
	list_attributes_copy(&modules, list_modules_meter, 0);
	list_attributes_comparator(&modules, list_modules_comparator);
	list_attributes_seeker(&modules, list_modules_seeker);

	lct_mutex_init(&modules_list_lock, NULL);

	modpath = lct_config_str(LCT_CONFIG_MODULES_PATH);
	if (modpath) {
		modules_path = modpath;
	}
	lct_cli_command_register("modules show", "Show loaded modules.", "modules show", handle_command_modules_show, NULL);

	/* Get the list of modules. */
	asprintf(&modspattern, "%s/*.so", modules_path);
	if (!modspattern) {
		lct_log(LCT_ERROR, "Unable to allocate space for the modules glob() pattern\n");
		return -1;
	}

	globbuf.gl_offs = 0;	/* initialize it to silence a gcc warning. */
	globret = glob(modspattern, MY_GLOB_FLAGS, NULL, &globbuf);
	if (globret == GLOB_NOSPACE) {
		lct_log(LCT_ERROR, "Glob espansion of pattern '%s' failed: Not enough memory\n", modspattern);
		free(modspattern);
		return -1;
	} else if (globret == GLOB_ABORTED) {
		lct_log(LCT_ERROR, "Glob expansion of pattern '%s' failed: Read error\n", modspattern);
		free(modspattern);
		return -1;
	}
	free(modspattern);

	for (i = 0; i < globbuf.gl_pathc; i++) {
		lct_log(LCT_DEBUG, "Loading module: %s\n", globbuf.gl_pathv[i]);
		if (lct_module_load(globbuf.gl_pathv[i]) < 0) {
			lct_log(LCT_ERROR, "Loading module: %s failed!\n", globbuf.gl_pathv[i]);
		}
	}

	globfree(&globbuf);

	return 0;
}

