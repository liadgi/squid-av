/* eCAP ClamAV Adapter                                http://www.e-cap.org/
 * Copyright (C) 2011 The Measurement Factory.
 * Distributed under GPL v2 without any warranty.                        */

#ifndef ECAP_CLAMAV_ADAPTER_ANTIVIRUS_H
#define ECAP_CLAMAV_ADAPTER_ANTIVIRUS_H

#include <libecap/common/forward.h>

//addition
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <getopt.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#include <jansson.h>

#include <VtFile.h>
#include <VtResponse.h>

namespace Adapter {

class Answer;

// generic virus scanner with support for blocking and asynchronous scans
// kids implement scanning-specific methods
class Antivirus
{
public:
    class User
    {
    public:
        virtual ~User() {}

        // handles the scanning result
        virtual void onAnswer(const Answer &answer) = 0;
    };

    typedef libecap::Options Options;

public:
    virtual ~Antivirus() {}

    virtual void configure(const Options &cfg) = 0;
    virtual void reconfigure(const Options &cfg) = 0;

    // refresh virus database, for example; does not change configuration
    virtual void update() = 0;

    // scan in the caller thread and call answer.deliver()
    void blockingScan(Answer &answer);

    // start scanning without blocking the caller
    // eventually "delivers" the answer via answer.deliver()
    // the answer object must be treated as invalid after this call
    void asyncScan(Answer *answer);

protected:
    // scan answer.filename and update the answer
    // called from either a scanner or a host thread
    //virtual void scan(Answer &answer) = 0;

    static void *AsyncScan(void *context);

    static bool keep_running;// = true;
    static void print_usage(const char *prog_name);
    long long get_file_size(const char *path);
    struct CallbackData {
        int counter;
    };

    static void sighand_callback(int sig);
    static void cluster_callback(json_t* cluster_json, void *data);
    static void progress_callback(struct VtFile *file, void *data);
    static int scan_file(struct VtFile *scan, const char *path);
    static int scan_stdinput(struct VtFile *scan, const char * file_name);
    static int main2(int argc, char **argv);


    static void scan(Answer &answer);
    static int report(const char * filename);

};

} // namaspace Adapter

#endif

