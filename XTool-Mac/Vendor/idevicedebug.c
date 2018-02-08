/*
 * idevicedebug.c
 * Interact with the debugserver service of a device.
 *
 * Copyright (c) 2014-2015 Martin Szulecki All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <libgen.h>

#ifdef WIN32
#include <windows.h>
#define sleep(x) Sleep(x*1000)
#endif

#include <libimobiledevice/installation_proxy.h>
#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/debugserver.h>
#include <plist/plist.h>
//#include "common/debug.h"


enum cmd_mode {
    CMD_NONE = 0,
    CMD_RUN
};

static int quit_flag = 0;

static void on_signal(int sig)
{
    fprintf(stderr, "Exiting...\n");
    quit_flag++;
}

static instproxy_error_t instproxy_client_get_object_by_key_from_info_directionary_for_bundle_identifier(instproxy_client_t client, const char* appid, const char* key, plist_t* node)
{
    if (!client || !appid || !key)
        return INSTPROXY_E_INVALID_ARG;
    
    plist_t apps = NULL;
    
    // create client options for any application types
    plist_t client_opts = instproxy_client_options_new();
    instproxy_client_options_add(client_opts, "ApplicationType", "Any", NULL);
    
    // only return attributes we need
    instproxy_client_options_set_return_attributes(client_opts, "CFBundleIdentifier", "CFBundleExecutable", key, NULL);
    
    // only query for specific appid
    const char* appids[] = {appid, NULL};
    
    // query device for list of apps
    instproxy_error_t ierr = instproxy_lookup(client, appids, client_opts, &apps);
    
    instproxy_client_options_free(client_opts);
    
    if (ierr != INSTPROXY_E_SUCCESS) {
        return ierr;
    }
    
    plist_t app_found = plist_access_path(apps, 1, appid);
    if (!app_found) {
        if (apps)
            plist_free(apps);
        *node = NULL;
        return INSTPROXY_E_OP_FAILED;
    }
    
    plist_t object = plist_dict_get_item(app_found, key);
    if (object) {
        *node = plist_copy(object);
    } else {
        //        printf("key %s not found", key);
        return INSTPROXY_E_OP_FAILED;
    }
    
    plist_free(apps);
    
    return INSTPROXY_E_SUCCESS;
}

static debugserver_error_t debugserver_client_handle_response(debugserver_client_t client, char** response, int send_reply)
{
    debugserver_error_t dres = DEBUGSERVER_E_SUCCESS;
    debugserver_command_t command = NULL;
    char* o = NULL;
    char* r = *response;
    
    if (r[0] == 'O') {
        /* stdout/stderr */
        debugserver_decode_string(r + 1, strlen(r) - 1, &o);
        printf("%s", o);
        fflush(stdout);
        if (o != NULL) {
            free(o);
            o = NULL;
        }
        
        free(*response);
        *response = NULL;
        
        if (!send_reply)
            return dres;
        
        /* send reply */
        debugserver_command_new("OK", 0, NULL, &command);
        dres = debugserver_client_send_command(client, command, response);
        //        printf("result: %d", dres);
        debugserver_command_free(command);
        command = NULL;
    } else if (r[0] == 'T') {
        /* thread stopped information */
        printf("Thread stopped. Details:\n%s", r + 1);
        
        free(*response);
        *response = NULL;
        
        if (!send_reply)
            return dres;
        
        dres = DEBUGSERVER_E_UNKNOWN_ERROR;
    } else if (r[0] == 'E' || r[0] == 'W') {
        printf("%s: %s\n", (r[0] == 'E' ? "ERROR": "WARNING") , r + 1);
        
        free(*response);
        *response = NULL;
        
        if (!send_reply)
            return dres;
        
        /* send reply */
        debugserver_command_new("OK", 0, NULL, &command);
        dres = debugserver_client_send_command(client, command, response);
        printf("result: %d", dres);
        debugserver_command_free(command);
        command = NULL;
    } else if (r && strlen(r) == 0) {
        if (!send_reply)
            return dres;
        
        free(*response);
        *response = NULL;
        
        /* no command */
        debugserver_command_new("OK", 0, NULL, &command);
        dres = debugserver_client_send_command(client, command, response);
        printf("result: %d", dres);
        debugserver_command_free(command);
        command = NULL;
    } else {
        printf("ERROR: unhandled response", r);
    }
    
    return dres;
}

static void print_usage(int argc, char **argv)
{
    char *name = NULL;
    name = strrchr(argv[0], '/');
    printf("Usage: %s [OPTIONS] COMMAND\n", (name ? name + 1: argv[0]));
    printf("Interact with the debugserver service of a device.\n\n");
    printf(" Where COMMAND is one of:\n");
    printf("  run BUNDLEID [ARGS...]\trun app with BUNDLEID and optional ARGS on device.\n");
    printf("\n");
    printf(" The following OPTIONS are accepted:\n");
    printf("  -e, --env NAME=VALUE\tset environment variable NAME to VALUE\n");
    printf("  -u, --udid UDID\ttarget specific device by its 40-digit device UDID\n");
    printf("  -d, --debug\t\tenable communication debugging\n");
    printf("  -h, --help\t\tprints usage information\n");
    printf("\n");
    //    printf("Homepage: <" PACKAGE_URL ">\n");
}

void launch_app(void)
{
    int res = -1;
    idevice_t device = NULL;
    idevice_error_t ret = IDEVICE_E_UNKNOWN_ERROR;
    instproxy_client_t instproxy_client = NULL;
    debugserver_client_t debugserver_client = NULL;
    int i;
    int debug_level = 0;
    int cmd = CMD_NONE;
    const char* udid = NULL;
    const char* bundle_identifier = NULL;
    char* path = NULL;
    char* working_directory = NULL;
    char **newlist = NULL;
    char** environment = NULL;
    int environment_index = 0;
    int environment_count = 0;
    char* response = NULL;
    debugserver_command_t command = NULL;
    debugserver_error_t dres = DEBUGSERVER_E_UNKNOWN_ERROR;
    
    /* map signals */
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
#ifndef WIN32
    signal(SIGQUIT, on_signal);
    signal(SIGPIPE, SIG_IGN);
#endif
    
    if (environment) {
        newlist = realloc(environment, (environment_count + 1) * sizeof(char*));
        newlist[environment_count] = NULL;
        environment = newlist;
    }
    
    
    bundle_identifier = "com.tttpeng.XTool";
    
    /* connect to the device */
    ret = idevice_new(&device, udid);
    if (ret != IDEVICE_E_SUCCESS) {
        if (udid) {
            printf("No device found with udid %s, is it plugged in?\n", udid);
        } else {
            printf("No device found, is it plugged in?\n");
        }
        goto cleanup;
    }
    
    /* get the path to the app and it's working directory */
    if (instproxy_client_start_service(device, &instproxy_client, "idevicerun") != INSTPROXY_E_SUCCESS) {
        fprintf(stderr, "Could not start installation proxy service.\n");
        goto cleanup;
    }
    plist_t container = NULL;
    instproxy_client_get_object_by_key_from_info_directionary_for_bundle_identifier(instproxy_client, bundle_identifier, "Container", &container);
    instproxy_client_get_path_for_bundle_identifier(instproxy_client, bundle_identifier, &path);
    instproxy_client_free(instproxy_client);
    instproxy_client = NULL;
    
    if (container && (plist_get_node_type(container) == PLIST_STRING)) {
        plist_get_string_val(container, &working_directory);
        printf("working_directory: %s\n", working_directory);
        plist_free(container);
    } else {
        plist_free(container);
        fprintf(stderr, "Could not determine container path for bundle identifier %s.\n", bundle_identifier);
        goto cleanup;
    }
    
    /* start and connect to debugserver */
    if (debugserver_client_start_service(device, &debugserver_client, "idevicerun") != DEBUGSERVER_E_SUCCESS) {
        fprintf(stderr,
                "Could not start com.apple.debugserver!\n"
                "Please make sure to mount the developer disk image first:\n"
                "  1) Get the iOS version from `ideviceinfo -k ProductVersion`.\n"
                "  2) Find the matching iPhoneOS DeveloperDiskImage.dmg files.\n"
                "  3) Run `ideviceimagemounter` with the above path.\n");
        goto cleanup;
    }
    
    
    /* set maximum packet size */
    printf("Setting maximum packet size...");
    char* packet_size[2] = {strdup("1024"), NULL};
    debugserver_command_new("QSetMaxPacketSize:", 1, packet_size, &command);
    free(packet_size[0]);
    dres = debugserver_client_send_command(debugserver_client, command, &response);
    debugserver_command_free(command);
    command = NULL;
    if (response) {
        if (strncmp(response, "OK", 2)) {
            debugserver_client_handle_response(debugserver_client, &response, 0);
            goto cleanup;
        }
        free(response);
        response = NULL;
    }
    
    /* set working directory */
    printf("Setting working directory...");
    char* working_dir[2] = {working_directory, NULL};
    debugserver_command_new("QSetWorkingDir:", 1, working_dir, &command);
    dres = debugserver_client_send_command(debugserver_client, command, &response);
    debugserver_command_free(command);
    command = NULL;
    if (response) {
        if (strncmp(response, "OK", 2)) {
            debugserver_client_handle_response(debugserver_client, &response, 0);
            goto cleanup;
        }
        free(response);
        response = NULL;
    }
    


    /* set arguments and run app */
    printf("Setting argv...");
    i++; /* i is the offset of the bundle identifier, thus skip it */
//    int app_argc = (argc - i + 2);
    char **app_argv = (char**)malloc(sizeof(char*) * 1);
    app_argv[0] = path;
    printf("app_argv[%d] = %s", 0, app_argv[0]);
//    app_argc = 1;

//    app_argv[app_argc] = NULL;
    debugserver_client_set_argv(debugserver_client, 1, app_argv, NULL);
    free(app_argv);

    
    
    /* check if launch succeeded */
    printf("Checking if launch succeeded...");
    debugserver_command_new("qLaunchSuccess", 0, NULL, &command);
    dres = debugserver_client_send_command(debugserver_client, command, &response);
    debugserver_command_free(command);
    command = NULL;
    if (response) {
        if (strncmp(response, "OK", 2)) {
            debugserver_client_handle_response(debugserver_client, &response, 0);
            goto cleanup;
        }
        free(response);
        response = NULL;
    }
    
    /* set thread */
    printf("Setting thread...");
    debugserver_command_new("Hc0", 0, NULL, &command);
    dres = debugserver_client_send_command(debugserver_client, command, &response);
    debugserver_command_free(command);
    command = NULL;
    if (response) {
        if (strncmp(response, "OK", 2)) {
            debugserver_client_handle_response(debugserver_client, &response, 0);
            goto cleanup;
        }
        free(response);
        response = NULL;
    }
    
    /* continue running process */
    printf("Continue running process...");
    debugserver_command_new("c", 0, NULL, &command);
    dres = debugserver_client_send_command(debugserver_client, command, &response);
    debugserver_command_free(command);
    command = NULL;
    
    /* main loop which is parsing/handling packets during the run */
//    printf("Entering run loop...");
//    while (!quit_flag) {
//        if (dres != DEBUGSERVER_E_SUCCESS) {
//            printf("failed to receive response");
//            break;
//        }
//
//        if (response) {
//            printf("response: %s", response);
//            dres = debugserver_client_handle_response(debugserver_client, &response, 1);
//        }
//
//        sleep(1);
//    }
    
    /* kill process after we finished */
//    printf("Killing process...");
//    debugserver_command_new("k", 0, NULL, &command);
//    dres = debugserver_client_send_command(debugserver_client, command, &response);
//    debugserver_command_free(command);
//    command = NULL;
//    if (response) {
//        if (strncmp(response, "OK", 2)) {
//            debugserver_client_handle_response(debugserver_client, &response, 0);
//            goto cleanup;
//        }
//        free(response);
//        response = NULL;
//    }
    
    res = (dres == DEBUGSERVER_E_SUCCESS) ? 0: -1;
    
cleanup:
    /* cleanup the house */
    if (environment) {
        for (environment_index = 0; environment_index < environment_count; environment_index++) {
            free(environment[environment_index]);
        }
        free(environment);
    }
    
    if (working_directory)
        free(working_directory);
    
    if (path)
        free(path);
    
    if (response)
        free(response);
    
    if (debugserver_client)
        debugserver_client_free(debugserver_client);
    
    if (device)
        idevice_free(device);
    
}

