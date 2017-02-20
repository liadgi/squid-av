/* eCAP ClamAV Adapter                                http://www.e-cap.org/
 * Copyright (C) 2011 The Measurement Factory.
 * Distributed under GPL v2 without any warranty.                        */

#include "Adapter.h"
#include "Antivirus.h"
#include "Async.h"
#include <utility>
#include <cstring>
#include <cassert>
#include <libecap/common/errors.h>

#include "Answer.h"
#include "Timeout.h"

#include "VtFile.h"
#include "VtResponse.h"

namespace Adapter {
    // The actual type of the Antivirus::AsyncScan(void*) parameter
    typedef std::pair<Antivirus *, Answer *> AsyncScanParam;
}

void Adapter::Antivirus::blockingScan(Answer &answer)
{
    //scan(answer);
    //keep_running = true;
    scan(answer);
    answer.deliver();
}

void Adapter::Antivirus::asyncScan(Answer *answer)
{
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    pthread_t id;
    AsyncScanParam *param = new AsyncScanParam(std::make_pair(this, answer));
    const int errNo = pthread_create(&id, &attr, &Adapter::Antivirus::AsyncScan, param);
    pthread_attr_destroy(&attr);
    if (errNo) {
        answer->statusCode = Answer::scError;
        answer->errorMsg = strerror(errNo); // TODO: make thread-safe
        answer->deliver(); // must destroy answer (eventually)
        delete param;
    }
    // else the thread becomes responsible for answer delivery
}

// Warning: This static method runs in a non-host thread!
void *Adapter::Antivirus::AsyncScan(void *param_)
{
    AsyncScanParam *param = static_cast<AsyncScanParam *>(param_);
    assert(param);
    Antivirus *self = param->first;
    Answer *answer = param->second;
    assert(self);
    assert(answer);
    self->scan(*answer);
    answer->deliver(); // must destroy answer (eventually)
    delete param;
    return 0;
}






void Adapter::Antivirus::sighand_callback(int sig)
{
  printf("signal caught %d\n", sig);
  //keep_running = false;
}

void Adapter::Antivirus::cluster_callback(json_t* cluster_json, void *data) {
  struct CallbackData *cb_data = (struct CallbackData *) data;
  char *s;

  cb_data->counter++;
  printf("------------- Result %d ----------------\n", cb_data->counter);

  s = json_dumps(cluster_json, JSON_INDENT(4));
  printf("%s \n", s);
  free(s);
  printf("\n");
}

void Adapter::Antivirus::progress_callback(struct VtFile *file, void *data)
{
  int64_t dltotal = 0;
  int64_t dlnow = 0;
  int64_t ul_total = 0;
  int64_t ul_now = 0;
  VtFile_getProgress(file, &dltotal, &dlnow, &ul_total, &ul_now);

  printf("progress_callback %lld/%lld\n", (long long) ul_now, (long long) ul_total);
  //if (!keep_running)
    //VtFile_cancelOperation(file);
}

#define RESP_BUF_SIZE 255

int Adapter::Antivirus::scan_file(struct VtFile *scan, const char *path)
{
  int ret;
  struct stat stat_buf;

  ret = stat(path, &stat_buf);

  if (ret)
    return ret;

  if (stat_buf.st_size < (64*1024*1024) ) {
    ret = VtFile_scan(scan, path, NULL);
  } else {
    ret = VtFile_scanBigFile(scan, path);
    printf(" VtFile_scanBigFile ret =%d \n", ret);
  }


  return ret;
}



int Adapter::Antivirus::scan_stdinput(struct VtFile *scan, const char * file_name)
{
  int ret;
#define MAX_SCAN_SIZE (32 * 1024 *1024)
  unsigned char *buff = NULL;
  size_t size_read;


  buff = (unsigned char *)malloc(MAX_SCAN_SIZE+1024);
  if (!buff)
    return -1;

  size_read = fread(buff, 1, MAX_SCAN_SIZE, stdin);
  if (size_read < 1) {
    printf("ERROR %d \n", (int) size_read);
    free(buff);
    return -1;
  }

  printf("read %d bytes\n",(int) size_read);

  // if filename not set, then set this required paramter
  if (!file_name || !file_name[0])
    file_name = "filename";

  ret = VtFile_scanMemBuf(scan, file_name, buff, size_read, NULL);

  free(buff);

  return ret;
}

#define RESP_BUF_SIZE 255
#define VT_RESPONSE_SUCCESS 1
#define VT_RESPONSE_QUEUED -2
#define VT_RESPONSE_UNPRESENT 0

void Adapter::Antivirus::scan(Answer &answer) {

    const char * api_key = "c78338272f4444e3ae2ea3b4d192bf46e84796757874d688ae2731858c1ef5be";
    const char * filename = answer.fileName.c_str();
    struct VtFile *file_scan;
    struct VtResponse *scanResponse, *reportResponse;
    char *strScan = NULL, *strReport = NULL;
    int ret = 0;
    int response_code;
    int positives;
    char buf[RESP_BUF_SIZE+1] = { 0, };
    bool isFileClean = false;

    signal(SIGHUP, sighand_callback);
    signal(SIGTERM, sighand_callback);

    file_scan = VtFile_new();
    VtFile_setProgressCallback(file_scan, progress_callback, NULL);
    VtFile_setApiKey(file_scan, api_key);


    ret = scan_file(file_scan, filename); // blocks
      if (ret) {
        printf("Error: %d \n", ret);
      } else {

        scanResponse = VtFile_getResponse(file_scan);
        ret = VtResponse_getResponseCode(scanResponse, &response_code);
        if (!ret)
        {
          strScan = VtResponse_toJSONstr(scanResponse, VT_JSON_FLAG_INDENT);
          if (strScan) {
            printf("Scan Response:\n%s\n", strScan);
            const char * resource = VtResponse_getString(scanResponse, "resource");

            // polling for scan report
            bool waitForReport = true;
            while (waitForReport) {
                ret = VtFile_report(file_scan, resource);
               // PRINT("rescan ret=%d\n", ret);
                if (ret) {
                  printf("Error: %d \n", ret);
                } else {
                    reportResponse = VtFile_getResponse(file_scan);
                    strReport = VtResponse_toJSONstr(reportResponse, VT_JSON_FLAG_INDENT);
                    if (strReport) {
                      printf("Report Response:\n%s\n", strReport);
                      free(strReport);
                    }

                    VtResponse_getVerboseMsg(reportResponse, buf, RESP_BUF_SIZE);
                    printf("Msg: %s\n", buf);

                    ret = VtResponse_getResponseCode(reportResponse, &response_code);
                    if (!ret) {
                        printf("Report response code: %d\n", response_code);
                        if (response_code == VT_RESPONSE_SUCCESS)
                        {
                          ret = VtResponse_getIntValue(reportResponse, "positives", &positives);
                          if (!ret) {
                            if (positives == 0) {
                              isFileClean = true;
                            } else {
                              isFileClean = false;
                            }
                            waitForReport = false;
                          }
                          
                        } else if (response_code == VT_RESPONSE_QUEUED) {

                        } else { // item not available

                        }
                      }

                        VtResponse_put(&reportResponse);
                    }
              if (waitForReport) {
                sleep(20);
              }
            }

            VtResponse_put(&scanResponse);

            if (!isFileClean) { // discovered dangerous file
              printf("Packet is dropped\n");
              answer.statusCode = Answer::scVirus;
            } else {
              printf("Forward packet\n");
              answer.statusCode = Answer::scClean;
            }
          } 
        }
      }
}

int Adapter::Antivirus::report(const char * filename) {
    
    char *str = NULL;
    int ret = 0;
    int response_code;
    struct VtFile *file_scan;
    struct VtResponse *response;
    char buf[RESP_BUF_SIZE+1] = { 0, };

    signal(SIGHUP, sighand_callback);
    signal(SIGTERM, sighand_callback);

    file_scan = VtFile_new();
    VtFile_setProgressCallback(file_scan, progress_callback, NULL);

    VtFile_setApiKey(file_scan, optarg);

      ret = VtFile_report(file_scan, optarg);
     // PRINT("rescan ret=%d\n", ret);
      if (ret) {
        printf("Error: %d \n", ret);
      } else {
        response = VtFile_getResponse(file_scan);
        str = VtResponse_toJSONstr(response, VT_JSON_FLAG_INDENT);
        if (str) {
          printf("Response:\n%s\n", str);
          free(str);
        }

        VtResponse_getVerboseMsg(response, buf, RESP_BUF_SIZE);
        printf("Msg: %s\n", buf);

        ret = VtResponse_getResponseCode(response, &response_code);
        if (!ret) {
          printf("response code: %d\n", response_code);
        }


        VtResponse_put(&response);
      }

      return 0;
}


int Adapter::Antivirus::main2(int argc, char **argv) {
  int c;
  int ret = 0;
  struct VtFile *file_scan;
  struct VtResponse *response;
  char *str = NULL;
  char *api_key = NULL;
  char *out = NULL;
  int response_code;
  struct CallbackData cb_data = { .counter = 0 };
  char buf[RESP_BUF_SIZE+1] = { 0, };

  if (argc < 2) {
    print_usage(argv[0]);
    return 0;
  }
  signal(SIGHUP, sighand_callback);
  signal(SIGTERM, sighand_callback);

  file_scan = VtFile_new();
  VtFile_setProgressCallback(file_scan, progress_callback, NULL);

  while (1) {
    int option_index = 0;
    static struct option long_options[] = {
      {"filescan",  required_argument,    0,  'f' },
      {"rescan",  required_argument,    0,  'r' },
      {"report",  required_argument,    0,  'i' },
      {"scaninput",  optional_argument,    0,  'I' },
      {"apikey",  required_argument,     0,  'a'},
      {"clusters",  required_argument,     0,  'c'},
      {"download",  required_argument,     0,  'd'},
      {"out",  required_argument,     0,  'o'},
      {"verbose", optional_argument,  0,  'v' },
      {"help", optional_argument,  0,  'h' },
      {0,         0,                 0,  0 }
    };

    c = getopt_long_only(argc, argv, "",
                         long_options, &option_index);
    if (c == -1)
      break;

    switch (c) {
    case 'a':
      api_key = strdup(optarg);
      printf(" apikey: %s \n", optarg);
      VtFile_setApiKey(file_scan, optarg);
      break;
    case 'c':

      if (!api_key) {
        printf("Must set --apikey first\n");
        exit(1);
      }
      ret = VtFile_clusters(file_scan, optarg,
                            cluster_callback, &cb_data);
      //PRINT("Filescan clusters ret=%d\n", ret);
      if (ret) {
        printf("Error: %d \n", ret);
      }
      break;
    case 'd':
      if (!api_key) {
        printf("Must set --apikey first\n");
        exit(1);
      }
      if (!out) {
        printf("Must set --out first\n");
        exit(1);
      }
      ret = VtFile_downloadToFile(file_scan, optarg, out);
      //PRINT("Filescan download ret=%d\n", ret);
      if (ret) {
        printf("Error: %d \n", ret);
      }
      break;
    case 'f':
      if (!api_key) {
        printf("Must set --apikey first\n");
        exit(1);
      }

      ret = scan_file(file_scan, optarg);
      // PRINT("Filescan ret=%d\n", ret);
      if (ret) {
        printf("Error: %d \n", ret);
      } else {
        response = VtFile_getResponse(file_scan);
        str = VtResponse_toJSONstr(response, VT_JSON_FLAG_INDENT);
        if (str) {
          printf("Response:\n%s\n", str);
          free(str);
        }
        VtResponse_put(&response);
      }
      break;
    case 'I': // scan from stdinput
      if (!api_key) {
        printf("Must set --apikey first\n");
        exit(1);
      }

      ret = scan_stdinput(file_scan, optarg);
      // PRINT("Filescan ret=%d\n", ret);
      if (ret) {
        printf("Error: %d \n", ret);
      } else {
        response = VtFile_getResponse(file_scan);
        str = VtResponse_toJSONstr(response, VT_JSON_FLAG_INDENT);
        if (str) {
          printf("Response:\n%s\n", str);
          free(str);
        }
        VtResponse_put(&response);
      }
      break;
    case 'r':
      if (!api_key) {
        printf("Must set --apikey first\n");
        exit(1);
      }

      ret = VtFile_rescanHash(file_scan, optarg, 0, 0, 0, NULL, false);
      // PRINT("rescan ret=%d\n", ret);
      if (ret) {
        printf("Error: %d \n", ret);
      } else {
        response = VtFile_getResponse(file_scan);
        str = VtResponse_toJSONstr(response, VT_JSON_FLAG_INDENT);
        if (str) {
          printf("Response:\n%s\n", str);
          free(str);
        }
        VtResponse_put(&response);
      }
      break;
    case 'i':
      if (!api_key) {
        printf("Must set --apikey first\n");
        exit(1);
      }
      ret = VtFile_report(file_scan, optarg);
     // PRINT("rescan ret=%d\n", ret);
      if (ret) {
        printf("Error: %d \n", ret);
      } else {
        response = VtFile_getResponse(file_scan);
        str = VtResponse_toJSONstr(response, VT_JSON_FLAG_INDENT);
        if (str) {
          printf("Response:\n%s\n", str);
          free(str);
        }

        VtResponse_getVerboseMsg(response, buf, RESP_BUF_SIZE);
        printf("Msg: %s\n", buf);

        ret = VtResponse_getResponseCode(response, &response_code);
        if (!ret) {
          printf("response code: %d\n", response_code);
        }


        VtResponse_put(&response);
      }
      break;
    case 'o':

      if (out)
        free(out);

      out = strdup(optarg);

      break;
    case 'h':
      print_usage(argv[0]);
      goto cleanup;
    case 'v':
      printf(" verbose selected\n");
      if (optarg)
        printf(" verbose level %s \n", optarg);
      break;
    default:
      printf("?? getopt returned character code 0%o ??\n", c);
    }
  } // end while

  if (optind < argc) {
    printf("non-option ARGV-elements: ");
    while (optind < argc)
      printf("%s ", argv[optind++]);
    printf("\n");
  }
cleanup:
  //PRINT("Cleanup\n");
  VtFile_put(&file_scan);

  if (api_key)
    free(api_key);

  if (out)
    free(out);

  return 0;
}
