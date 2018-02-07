//
//  ideviceinstaller.c
//  XTool-Mac
//
//  Created by tpeng on 2018/2/7.
//  Copyright © 2018年 tpeng. All rights reserved.
//

#include "ideviceinstaller.h"
#include "plist.h"
#include "libimobiledevice.h"
#include "installation_proxy.h"
#include "notification_proxy.h"
#include "afc.h"
#include "zip.h"

#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <time.h>
#include <libgen.h>
#include <inttypes.h>
#include <limits.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdlib.h>


static void print_apps_header()
{
    /* output app details header */
    printf("%s", "CFBundleIdentifier");
    printf(", %s", "CFBundleVersion");
    printf(", %s", "CFBundleDisplayName");
    printf("\n");
}

static void status_cb(plist_t command, plist_t status, void *unused)
{
    
    char *last_status = NULL;

    if (command && status) {
        char* command_name = NULL;
        instproxy_command_get_name(command, &command_name);
        
        /* get status */
        char *status_name = NULL;
        instproxy_status_get_name(status, &status_name);
        
        if (status_name) {
            if (!strcmp(status_name, "Complete")) {
            }
        }
        
        /* get error if any */
        char* error_name = NULL;
        char* error_description = NULL;
        uint64_t error_code = 0;
        instproxy_status_get_error(status, &error_name, &error_description, &error_code);
        
        /* output/handling */
        if (!error_name) {
            if (!strcmp(command_name, "Browse")) {
                uint64_t total = 0;
                uint64_t current_index = 0;
                uint64_t current_amount = 0;
                plist_t current_list = NULL;
                instproxy_status_get_current_list(status, &total, &current_index, &current_amount, &current_list);
                if (current_list) {
                    print_apps(current_list);
                    plist_free(current_list);
                }
            } else {
                /* get progress if any */
                int percent = -1;
                instproxy_status_get_percent_complete(status, &percent);
                
                if (last_status && (strcmp(last_status, status_name))) {
                    printf("\r");
                }
                
                if (percent >= 0) {
                    printf("%s: %s (%d%%)\n", command_name, status_name, percent);
                } else {
                    printf("%s: %s\n", command_name, status_name);
                }
            }
        } else {
            /* report error to the user */
            if (error_description)
                fprintf(stderr, "ERROR: %s failed. Got error \"%s\" with code 0x%08"PRIx64": %s\n", command_name, error_name, error_code, error_description ? error_description: "N/A");
            else
                fprintf(stderr, "ERROR: %s failed. Got error \"%s\".\n", command_name, error_name);
        }
        
        /* clean up */
        if (error_name)
            free(error_name);
        
        if (error_description)
            free(error_description);
        
        if (last_status) {
            free(last_status);
            last_status = NULL;
        }
        
        if (status_name) {
            last_status = strdup(status_name);
            free(status_name);
        }
        
        if (command_name) {
            free(command_name);
            command_name = NULL;
        }
    } else {
        fprintf(stderr, "ERROR: %s was called with invalid arguments!\n", __func__);
    }
}
void list_app() {
    char *udid = "4aadb25b782aa93f9f71af4ccf8e05d31150afc4";
    
    idevice_t phone = NULL;
    lockdownd_client_t client = NULL;
    instproxy_client_t ipc = NULL;
    instproxy_error_t err;
    np_client_t np = NULL;
    afc_client_t afc = NULL;
    lockdownd_service_descriptor_t service = NULL;
    int res = 0;
    char *bundleidentifier = NULL;
    
    if (IDEVICE_E_SUCCESS != idevice_new(&phone, udid)) {
        fprintf(stderr, "No iOS device found, is it plugged in?\n");
    }
    
    if (LOCKDOWN_E_SUCCESS != lockdownd_client_new_with_handshake(phone, &client, "ideviceinstaller")) {
        fprintf(stderr, "Could not connect to lockdownd. Exiting.\n");
    }
    
    if ((lockdownd_start_service
         (client, "com.apple.mobile.notification_proxy",
          &service) != LOCKDOWN_E_SUCCESS) || !service) {
             fprintf(stderr,
                     "Could not start com.apple.mobile.notification_proxy!\n");
         }
    
    np_error_t nperr = np_client_new(phone, service, &np);

    err = instproxy_client_new(phone, service, &ipc);

    printf("errrrrroorr --- %d\n",err);
    if (service) {
        lockdownd_service_descriptor_free(service);
    }
    service = NULL;
    
    if (nperr != NP_E_SUCCESS) {
        fprintf(stderr, "Could not connect to notification_proxy!\n");
    }
    
    
    const char *noties[3] = { NP_APP_INSTALLED, NP_APP_UNINSTALLED, NULL };
    
    np_observe_notifications(np, noties);

    
    
//-----
    if (service) {
        lockdownd_service_descriptor_free(service);
    }
    service = NULL;
    
    if ((lockdownd_start_service(client, "com.apple.mobile.installation_proxy",
                                 &service) != LOCKDOWN_E_SUCCESS) || !service) {
        fprintf(stderr,
                "Could not start com.apple.mobile.installation_proxy!\n");
    }
    
    err = instproxy_client_new(phone, service, &ipc);
    
    if (service) {
        lockdownd_service_descriptor_free(service);
    }
    service = NULL;
    
    if (err != INSTPROXY_E_SUCCESS) {
        fprintf(stderr, "Could not connect to installation_proxy!\n");
    }
    
    setbuf(stdout, NULL);

    
    
//------
    
    
    
    plist_t client_opts = instproxy_client_options_new();
    instproxy_client_options_add(client_opts, "ApplicationType", "User", NULL);
    plist_t apps = NULL;
    
    instproxy_client_options_set_return_attributes(client_opts,
                                                   "CFBundleIdentifier",
                                                   "CFBundleDisplayName",
                                                   "CFBundleVersion",
                                                   "StaticDiskUsage",
                                                   "DynamicDiskUsage",
                                                   NULL
                                                   );
    
    err = instproxy_browse(ipc, client_opts, &apps);
    printf("error --- %d\n",err);
    
    if (!apps || (plist_get_node_type(apps) != PLIST_ARRAY)) {
        fprintf(stderr,
                "ERROR: instproxy_browse returnd an invalid plist!\n");
    }
    
    char *xml = NULL;
    uint32_t len = 0;
    
    plist_to_xml(apps, &xml, &len);
    if (xml) {
        puts(xml);
        free(xml);
    }
    plist_free(apps);
    
    
    printf("Total: %d archived apps\n", plist_dict_get_size(apps));
    
    
    
    
    
    //    plist_dict_new_iter(dict, &iter);
    //    do {
    //        key = NULL;
    //        node = NULL;
    //        plist_dict_next_item(dict, iter, &key, &node);
    //        if (key && (plist_get_node_type(node) == PLIST_DICT)) {
    //            char *s_dispName = NULL;
    //            char *s_version = NULL;
    //            plist_t dispName =
    //            plist_dict_get_item(node, "CFBundleDisplayName");
    //            plist_t version =
    //            plist_dict_get_item(node, "CFBundleVersion");
    //            if (dispName) {
    //                plist_get_string_val(dispName, &s_dispName);
    //            }
    //            if (version) {
    //                plist_get_string_val(version, &s_version);
    //            }
    //            if (!s_dispName) {
    //                s_dispName = strdup(key);
    //            }
    //            if (s_version) {
    //                printf("%s - %s %s\n", key, s_dispName, s_version);
    //                free(s_version);
    //            } else {
    //                printf("%s - %s\n", key, s_dispName);
    //            }
    //            free(s_dispName);
    //            free(key);
    //        }
    //    }
    //    while (node);
    //
    
    
    //
    //    int xml_mode = 0;
    //    plist_t client_opts = instproxy_client_options_new();
    //    instproxy_client_options_add(client_opts, "ApplicationType", "User", NULL);
    //    plist_t apps = NULL;
    //
    //
    //    if (!xml_mode) {
    //        instproxy_client_options_set_return_attributes(client_opts,
    //                                                       "CFBundleIdentifier",
    //                                                       "CFBundleDisplayName",
    //                                                       "CFBundleVersion",
    //                                                       "StaticDiskUsage",
    //                                                       "DynamicDiskUsage",
    //                                                       NULL
    //                                                       );
    //    }
    //
    //    if (xml_mode) {
    //        err = instproxy_browse(ipc, client_opts, &apps);
    //
    //        if (!apps || (plist_get_node_type(apps) != PLIST_ARRAY)) {
    //            fprintf(stderr,
    //                    "ERROR: instproxy_browse returnd an invalid plist!\n");
    ////    //        }
    //
    //        char *xml = NULL;
    //        uint32_t len = 0;
    //
    //        plist_to_xml(apps, &xml, &len);
    //        if (xml) {
    //            puts(xml);
    ////            free(xml);
    //        }
    //        plist_free(apps);
    ////        goto leave_cleanup;
    //    }
    //
    //    print_apps_header();
    char *appid = NULL;
    const char PKG_PATH[] = "PublicStaging";
    const char APPARCH_PATH[] = "ApplicationArchives";
#define ITUNES_METADATA_PLIST_FILENAME "iTunesMetadata.plist"

    
    appid = strdup(optarg);
    
    plist_t sinf = NULL;
    plist_t meta = NULL;
    char *pkgname = NULL;
    struct stat fst;
    uint64_t af = 0;
    char buf[8192];
    
    if (service) {
        lockdownd_service_descriptor_free(service);
    }
    service = NULL;
    
    if ((lockdownd_start_service(client, "com.apple.afc", &service) !=
         LOCKDOWN_E_SUCCESS) || !service) {
        fprintf(stderr, "Could not start com.apple.afc!\n");
    }
    
    lockdownd_client_free(client);
    client = NULL;
    
    if (afc_client_new(phone, service, &afc) != AFC_E_SUCCESS) {
        fprintf(stderr, "Could not connect to AFC!\n");
    }
    
    if (stat(appid, &fst) != 0) {
        fprintf(stderr, "ERROR: stat: %s: %s\n", appid, strerror(errno));
    }
    
    char **strs = NULL;
    if (afc_get_file_info(afc, PKG_PATH, &strs) != AFC_E_SUCCESS) {
        if (afc_make_directory(afc, PKG_PATH) != AFC_E_SUCCESS) {
            fprintf(stderr, "WARNING: Could not create directory '%s' on device!\n", PKG_PATH);
        }
    }
    if (strs) {
        int i = 0;
        while (strs[i]) {
            free(strs[i]);
            i++;
        }
        free(strs);
    }
    
    
    /* open install package */
    int errp = 0;
    struct zip *zf = NULL;
    
    if ((strlen(appid) > 5) && (strcmp(&appid[strlen(appid)-5], ".ipcc") == 0)) {
        zf = zip_open(appid, 0, &errp);
        if (!zf) {
            fprintf(stderr, "ERROR: zip_open: %s: %d\n", appid, errp);
        }
        
        char* ipcc = strdup(appid);
        if ((asprintf(&pkgname, "%s/%s", PKG_PATH, basename(ipcc)) > 0) && pkgname) {
            afc_make_directory(afc, pkgname);
        }
        
        printf("Uploading %s package contents... ", basename(ipcc));
        
        /* extract the contents of the .ipcc file to PublicStaging/<name>.ipcc directory */
        zip_uint64_t numzf = zip_get_num_entries(zf, 0);
        zip_uint64_t i = 0;
        for (i = 0; numzf > 0 && i < numzf; i++) {
            const char* zname = zip_get_name(zf, i, 0);
            char* dstpath = NULL;
            if (!zname) continue;
            if (zname[strlen(zname)-1] == '/') {
                // directory
                if ((asprintf(&dstpath, "%s/%s/%s", PKG_PATH, basename(ipcc), zname) > 0) && dstpath) {
                    afc_make_directory(afc, dstpath);                        }
                free(dstpath);
                dstpath = NULL;
            } else {
                // file
                struct zip_file* zfile = zip_fopen_index(zf, i, 0);
                if (!zfile) continue;
                
                if ((asprintf(&dstpath, "%s/%s/%s", PKG_PATH, basename(ipcc), zname) <= 0) || !dstpath || (afc_file_open(afc, dstpath, AFC_FOPEN_WRONLY, &af) != AFC_E_SUCCESS)) {
                    fprintf(stderr, "ERROR: can't open afc://%s for writing\n", dstpath);
                    free(dstpath);
                    dstpath = NULL;
                    zip_fclose(zfile);
                    continue;
                }
                
                struct zip_stat zs;
                zip_stat_init(&zs);
                if (zip_stat_index(zf, i, 0, &zs) != 0) {
                    fprintf(stderr, "ERROR: zip_stat_index %" PRIu64 " failed!\n", i);
                    free(dstpath);
                    dstpath = NULL;
                    zip_fclose(zfile);
                    continue;
                }
                
                free(dstpath);
                dstpath = NULL;
                
                zip_uint64_t zfsize = 0;
                while (zfsize < zs.size) {
                    zip_int64_t amount = zip_fread(zfile, buf, sizeof(buf));
                    if (amount == 0) {
                        break;
                    }
                    
                    if (amount > 0) {
                        uint32_t written, total = 0;
                        while (total < amount) {
                            written = 0;
                            if (afc_file_write(afc, af, buf, amount, &written) !=
                                AFC_E_SUCCESS) {
                                fprintf(stderr, "AFC Write error!\n");
                                break;
                            }
                            total += written;
                        }
                        if (total != amount) {
                            fprintf(stderr, "Error: wrote only %d of %" PRIi64 "\n", total, amount);
                            afc_file_close(afc, af);
                            zip_fclose(zfile);
                            free(dstpath);
                        }
                    }
                    
                    zfsize += amount;
                }
                
                afc_file_close(afc, af);
                af = 0;
                
                zip_fclose(zfile);
            }
        }
        free(ipcc);
        printf("DONE.\n");
        
        instproxy_client_options_add(client_opts, "PackageType", "CarrierBundle", NULL);
    } else if (S_ISDIR(fst.st_mode)) {
        /* upload developer app directory */
        instproxy_client_options_add(client_opts, "PackageType", "Developer", NULL);
        
        if (asprintf(&pkgname, "%s/%s", PKG_PATH, basename(appid)) < 0) {
            fprintf(stderr, "ERROR: Out of memory allocating pkgname!?\n");
        }
        
        printf("Uploading %s package contents... ", basename(appid));
        afc_upload_dir(afc, appid, pkgname);
        printf("DONE.\n");
    } else {
        zf = zip_open(appid, 0, &errp);
        if (!zf) {
            fprintf(stderr, "ERROR: zip_open: %s: %d\n", appid, errp);
        }
        
        /* extract iTunesMetadata.plist from package */
        char *zbuf = NULL;
        uint32_t len = 0;
        plist_t meta_dict = NULL;
        if (zip_get_contents(zf, ITUNES_METADATA_PLIST_FILENAME, 0, &zbuf, &len) == 0) {
            meta = plist_new_data(zbuf, len);
            if (memcmp(zbuf, "bplist00", 8) == 0) {
                plist_from_bin(zbuf, len, &meta_dict);
            } else {
                plist_from_xml(zbuf, len, &meta_dict);
            }
        } else {
            fprintf(stderr, "WARNING: could not locate %s in archive!\n", ITUNES_METADATA_PLIST_FILENAME);
        }
        if (zbuf) {
            free(zbuf);
        }
        
        /* determine .app directory in archive */
        zbuf = NULL;
        len = 0;
        plist_t info = NULL;
        char* filename = NULL;
        char* app_directory_name = NULL;
        
        if (zip_get_app_directory(zf, &app_directory_name)) {
            fprintf(stderr, "Unable to locate app directory in archive!\n");
        }
        
        /* construct full filename to Info.plist */
        filename = (char*)malloc(strlen(app_directory_name)+10+1);
        strcpy(filename, app_directory_name);
        free(app_directory_name);
        app_directory_name = NULL;
        strcat(filename, "Info.plist");
        
        if (zip_get_contents(zf, filename, 0, &zbuf, &len) < 0) {
            fprintf(stderr, "WARNING: could not locate %s in archive!\n", filename);
            free(filename);
            zip_unchange_all(zf);
            zip_close(zf);
        }
        free(filename);
        if (memcmp(zbuf, "bplist00", 8) == 0) {
            plist_from_bin(zbuf, len, &info);
        } else {
            plist_from_xml(zbuf, len, &info);
        }
        free(zbuf);
        
        if (!info) {
            fprintf(stderr, "Could not parse Info.plist!\n");
            zip_unchange_all(zf);
            zip_close(zf);
        }
        
        char *bundleexecutable = NULL;
        
        plist_t bname = plist_dict_get_item(info, "CFBundleExecutable");
        if (bname) {
            plist_get_string_val(bname, &bundleexecutable);
        }
        
        bname = plist_dict_get_item(info, "CFBundleIdentifier");
        if (bname) {
            plist_get_string_val(bname, &bundleidentifier);
        }
        plist_free(info);
        info = NULL;
        
        if (!bundleexecutable) {
            fprintf(stderr, "Could not determine value for CFBundleExecutable!\n");
            zip_unchange_all(zf);
            zip_close(zf);
        }
        
        char *sinfname = NULL;
        if (asprintf(&sinfname, "Payload/%s.app/SC_Info/%s.sinf", bundleexecutable, bundleexecutable) < 0) {
            fprintf(stderr, "Out of memory!?\n");
        }
        free(bundleexecutable);
        
        /* extract .sinf from package */
        zbuf = NULL;
        len = 0;
        if (zip_get_contents(zf, sinfname, 0, &zbuf, &len) == 0) {
            sinf = plist_new_data(zbuf, len);
        } else {
            fprintf(stderr, "WARNING: could not locate %s in archive!\n", sinfname);
        }
        free(sinfname);
        if (zbuf) {
            free(zbuf);
        }
        
        /* copy archive to device */
        pkgname = NULL;
        if (asprintf(&pkgname, "%s/%s", PKG_PATH, bundleidentifier) < 0) {
            fprintf(stderr, "Out of memory!?\n");
        }
        
        printf("Copying '%s' to device... ", appid);
        
        if (afc_upload_file(afc, appid, pkgname) < 0) {
            free(pkgname);
        }
        
        printf("DONE.\n");
        
        if (bundleidentifier) {
            instproxy_client_options_add(client_opts, "CFBundleIdentifier", bundleidentifier, NULL);
        }
        if (sinf) {
            instproxy_client_options_add(client_opts, "ApplicationSINF", sinf, NULL);
        }
        if (meta) {
            instproxy_client_options_add(client_opts, "iTunesMetadata", meta, NULL);
        }
    }
    if (zf) {
        zip_unchange_all(zf);
        zip_close(zf);
    }
    
        printf("Installing '%s'\n", bundleidentifier);
        instproxy_install(ipc, pkgname, client_opts, status_cb, NULL);
    instproxy_client_options_free(client_opts);
    free(pkgname);
}




