/*
 * auth-script OpenVPN plugin
 * 
 * Runs an external script to decide whether to authenticate a user or not.
 * Useful for checking 2FA on VPN auth attempts as it doesn't block the main
 * openvpn process, unlike passing the script to --auth-user-pass-verify.
 * 
 * Functions required to be a valid OpenVPN plugin:
 * openvpn_plugin_open_v3
 * openvpn_plugin_func_v3
 * openvpn_plugin_close_v1
 */

/* Required to use strdup */
#define __EXTENSIONS__

/********** Includes */
#include <stddef.h>
#include <errno.h>
#include <openvpn-plugin.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>

/********** Constants */
/* For consistency in log messages */
#define PLUGIN_NAME "auth-script"
#define OPENVPN_PLUGIN_VERSION_MIN 3
#define SCRIPT_NAME_IDX 0

/* Where we store our own settings/state */
struct plugin_context 
{
        plugin_log_t plugin_log;
        const char *argv[];
};

/* Extract environment variables from envp */
static const char* get_env(const char *name, const char *envp[]) {
    if (envp) {
        int i = 0;
        const char *entry = NULL;
        const size_t namelen = strlen(name);
        while ((entry = envp[i++]) != NULL) {
            if (strncmp(entry, name, namelen) == 0 && entry[namelen] == '=') {
                return &entry[namelen + 1]; // Returns value after '='
            }
        }
    }
    return NULL;
}

/* Handle an authentication request */
/* Modified deferred_handler function */
static int deferred_handler(struct plugin_context *context, const char *envp[])
{
    plugin_log_t log = context->plugin_log;
    pid_t pid;

    /* Extract username and password from environment variables */
    const char* username = get_env("username", envp);
    const char* password = get_env("password", envp);

    if (!username || !password) {
        log(PLOG_ERR, PLUGIN_NAME, "Username or password not provided");
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    log(PLOG_DEBUG, PLUGIN_NAME, "Deferred handler using script_path=%s", context->argv[SCRIPT_NAME_IDX]);

    /* Fork and handle the authentication script */
    pid = fork();

    if (pid < 0) { // Fork failed
        log(PLOG_ERR, PLUGIN_NAME, "Fork failed with error code: %d", pid);
        return OPENVPN_PLUGIN_FUNC_ERROR;
    } else if (pid > 0) { // Parent process
        int wstatus;
        pid_t wait_rc = waitpid(pid, &wstatus, 0);
        if (wait_rc < 0) {
            log(PLOG_ERR, PLUGIN_NAME, "Wait failed for pid %d, waitpid got %d", pid, wait_rc);
            return OPENVPN_PLUGIN_FUNC_ERROR;
        }
        if (WIFEXITED(wstatus)) {
            log(PLOG_DEBUG, PLUGIN_NAME, "Child exited with status %d", WEXITSTATUS(wstatus));
            return WEXITSTATUS(wstatus);
        }
        log(PLOG_ERR, PLUGIN_NAME, "Child terminated abnormally");
        return OPENVPN_PLUGIN_FUNC_ERROR;
    } else { // Child process
        /* Construct new argv with username and password */
        char *new_argv[] = {context->argv[0], strdup(username), strdup(password), NULL};

        /* Execute the authentication script with the new argv */
        execve(context->argv[0], new_argv, (char *const *)envp);
        exit(EXIT_FAILURE); // Should never reach here unless execve fails
    }
}

/* We require OpenVPN Plugin API v3 */
OPENVPN_EXPORT int openvpn_plugin_min_version_required_v1()
{
        return OPENVPN_PLUGIN_VERSION_MIN;
}

/* 
 * Handle plugin initialization
 *        arguments->argv[0] is path to shared lib
 *        arguments->argv[1] is expected to be path to script
 */
OPENVPN_EXPORT int openvpn_plugin_open_v3(const int struct_version,
                struct openvpn_plugin_args_open_in const *arguments,
                struct openvpn_plugin_args_open_return *retptr)
{
        plugin_log_t log = arguments->callbacks->plugin_log;
        log(PLOG_DEBUG, PLUGIN_NAME, "FUNC: openvpn_plugin_open_v3");

        struct plugin_context *context = NULL;

        /* Safeguard on openvpn versions */
        if (struct_version < OPENVPN_PLUGINv3_STRUCTVER) {
                log(PLOG_ERR, PLUGIN_NAME, 
                                "ERROR: struct version was older than required");
                return OPENVPN_PLUGIN_FUNC_ERROR;
        }

        /* Tell OpenVPN we want to handle these calls */
        retptr->type_mask = OPENVPN_PLUGIN_MASK(
                        OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY);

        
        /*
         * Determine the size of the arguments provided so we can allocate and
         * argv array of appropriate length.
         */
        size_t arg_size = 0;
        for (int arg_idx = 1; arguments->argv[arg_idx]; arg_idx++)
                arg_size += strlen(arguments->argv[arg_idx]);


        /* 
         * Plugin init will fail unless we create a handler, so we'll store our
         * script path and it's arguments there as we have to create it anyway. 
         */
        context = (struct plugin_context *) malloc(
                        sizeof(struct plugin_context) + arg_size);
        memset(context, 0, sizeof(struct plugin_context) + arg_size);
        context->plugin_log = log;


        /* 
         * Check we've been handed a script path to call
         * This comes directly from openvpn config file:
         *           plugin /path/to/auth.so /path/to/auth/script.sh
         *
         * IDX 0 should correspond to the library, IDX 1 should be the
         * script, and any subsequent entries should be arguments to the script.
         *
         * Note that if arg_size is 0 no script argument was included.
         */
        if (arg_size > 0) {
                memcpy(&context->argv, &arguments->argv[1], arg_size);

                log(PLOG_DEBUG, PLUGIN_NAME, 
                                "script_path=%s", 
                                context->argv[SCRIPT_NAME_IDX]);
        } else {
                free(context);
                log(PLOG_ERR, PLUGIN_NAME, 
                                "ERROR: no script_path specified in config file");
                return OPENVPN_PLUGIN_FUNC_ERROR;
        }        

        /* Pass state back to OpenVPN so we get handed it back later */
        retptr->handle = (openvpn_plugin_handle_t) context;

        log(PLOG_DEBUG, PLUGIN_NAME, "plugin initialized successfully");

        return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

/* Called when we need to handle OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY calls */
OPENVPN_EXPORT int openvpn_plugin_func_v3(const int struct_version,
                struct openvpn_plugin_args_func_in const *arguments,
                struct openvpn_plugin_args_func_return *retptr)
{
        (void)retptr; /* Squish -Wunused-parameter warning */
        struct plugin_context *context = 
                (struct plugin_context *) arguments->handle;
        plugin_log_t log = context->plugin_log;

        log(PLOG_DEBUG, PLUGIN_NAME, "FUNC: openvpn_plugin_func_v3");

        /* Safeguard on openvpn versions */
        if (struct_version < OPENVPN_PLUGINv3_STRUCTVER) {
                log(PLOG_ERR, PLUGIN_NAME, 
                                "ERROR: struct version was older than required");
                return OPENVPN_PLUGIN_FUNC_ERROR;
        }

        if(arguments->type == OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY) {
                log(PLOG_DEBUG, PLUGIN_NAME,
                                "Handling auth with deferred script");
                return deferred_handler(context, arguments->envp);
        } else
                return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

OPENVPN_EXPORT void openvpn_plugin_close_v1(openvpn_plugin_handle_t handle)
{
        struct plugin_context *context = (struct plugin_context *) handle;
        free(context);
}
