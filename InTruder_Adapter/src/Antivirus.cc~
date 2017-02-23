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
        answer->errorMsg = strerror(errNo);
        answer->deliver();
        delete param;
    }
}

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
}

// Shows the progress while interacting with VirusTotal API
void Adapter::Antivirus::progress_callback(struct VtFile *file, void *data)
{
  int64_t dltotal = 0;
  int64_t dlnow = 0;
  int64_t ul_total = 0;
  int64_t ul_now = 0;
  VtFile_getProgress(file, &dltotal, &dlnow, &ul_total, &ul_now);

  printf("progress_callback %lld/%lld\n", (long long) ul_now, (long long) ul_total);
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




#define RESP_BUF_SIZE 255
#define VT_RESPONSE_SUCCESS 1
#define VT_RESPONSE_QUEUED -2
#define VT_RESPONSE_UNPRESENT 0


// This method is responsible for both validating the file against VirusTotal, and detecting it for
// being a possible ransomware. 
void Adapter::Antivirus::scan(Answer &answer) {

    // In production mode would be stored in config file with permissions for squid process only
    const char * api_key = "c78338272f4444e3ae2ea3b4d192bf46e84796757874d688ae2731858c1ef5be";


    const char * filename = answer.fileName.c_str();
    struct VtFile *file_scan;
    struct VtResponse *scanResponse, *reportResponse;
    char *strScan = NULL, *strReport = NULL;
    int ret = 0;
    int response_code;
    int positives;
    char buf[RESP_BUF_SIZE+1] = { 0, };
    bool isFileClean = true;
    bool shouldScanForRansomware = true;

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

            // a Resource is attached to every scanned file. We will use it when asking for scan results
            const char * resource = VtResponse_getString(scanResponse, "resource");

            // polling until scan report is done
            bool waitingForReport = true;
            while (waitingForReport) {

                // ask for the scan report
                ret = VtFile_report(file_scan, resource);
                if (ret) {
                  printf("Error: %d \n", ret);
                } else {
                    reportResponse = VtFile_getResponse(file_scan);
                    strReport = VtResponse_toJSONstr(reportResponse, VT_JSON_FLAG_INDENT);
                    if (strReport) {
                      printf("Report Response:\n%s\n", strReport);
                      free(strReport);
                    }

                    // printing the message recieved from VirusTotal
                    VtResponse_getVerboseMsg(reportResponse, buf, RESP_BUF_SIZE);
                    printf("Msg: %s\n", buf);

                    ret = VtResponse_getResponseCode(reportResponse, &response_code);
                    if (!ret) {
                        printf("Report response code: %d\n", response_code);
                        if (response_code == VT_RESPONSE_SUCCESS)
                        {
                          // VirusTotal finished scanning the file and created a final scan report.
                          // We read how many antivirus programs detected the file as malicious by the JSON "positives" field
                          ret = VtResponse_getIntValue(reportResponse, "positives", &positives);
                          if (!ret) {
                            if (positives == 0) {
                              printf("VirusTotal scan - At least one positive result - file is dangerous\n");
                              isFileClean = true;
                            } else {
                              printf("VirusTotal scan - Not a single positive result - file is safe\n");
                              isFileClean = false;
                            }

                            // After determining the file's status, we can stop polling
                            waitingForReport = false; 
                          }
                        } 
                      }

                        VtResponse_put(&reportResponse);
                    }

              // The section which the file is scanned for potentially being ransomware
              if (shouldScanForRansomware && isFileClean) {
                  isFileClean = !isPossibleRansomware(answer.fileName.c_str());

                  if (!isFileClean) {
                    // File is suspicious for being ransomware, no need to wait for VirusTotal incase it's still in progress
                    waitingForReport = false;
                  }

                  // After scaning once, there's no need to scan again
                  shouldScanForRansomware = false;
              }
              if (waitingForReport) {

                // Simple mechanism, if squid is configured with 'async=yes' option no lock should occur
                sleep(20); // should also be in configuration file
              }
            }

            VtResponse_put(&scanResponse);

            if (!isFileClean) { 
              printf("Access Denied\n");
              answer.statusCode = Answer::scVirus;
            } else {
              printf("Access Granted\n");
              answer.statusCode = Answer::scClean;
            }
          } 
        } 
      }
} 

// Compares two characters. If equal, returns 0. If the first is lexicography bigger, returns 1. Else, returns -1
int memcompare(const unsigned char *s1, const unsigned char *s2, size_t n){
    unsigned int i;
    for (i=0; i<n; i++) {
      if (*((unsigned char*)(s1+i)) > *((unsigned char*)(s2+i))) {
        return 1;
      } else if (*((unsigned char*)(s1+i)) < *((unsigned char*)(s2+i))) {
        return -1;
      }
    }
    
    return 0;
}


// Receives a buffer, a signature and size of that buffer and determines whether the buffer contains that signature
bool Adapter::Antivirus::containsCode(unsigned char *buffer, unsigned char signature[_signaturesScanSize], unsigned int size) {
    unsigned int i;
    int cmpRes;
    printf("code detection started. size: %d, _signaturesScanSize: %d\n", size, _signaturesScanSize);
    for (i = 0; i < size-_signaturesScanSize; i++) {
            cmpRes = memcmp(buffer+i, signature, _signaturesScanSize);
            if (cmpRes == 0) {
                printf("code detection done\n");
                return true;
            }
    }
    printf("code detection done\n");
    return false;
}


// Determines whether the file contains the signature of EVP_SealInit while not containing the corresponding EVP_OpenInit.
bool Adapter::Antivirus::isPossibleRansomware(const char* fileName) {
    bool isMalicious = false;// Assuming the file is legit in the first place

    unsigned int res; // general result of system calls
    unsigned int lSize; // size of inspected file
    unsigned char sealInitSignature[_signaturesScanSize];

    // Opening signature file and copying to memory
    FILE * sealInitFile = fopen("/etc/sealinit_sig", "r");
     if (sealInitFile == NULL) {
      printf("Opening sealInitFile error\n");
      //exit(1);
    }
    // read the EVP_SealInit signature from the file to the buffer
    res = fread(sealInitSignature, 1, _signaturesScanSize, sealInitFile);
    if (res != _signaturesScanSize) {
        printf("Reading from sealInitFile error\n");
    }
    fclose(sealInitFile);



    // Opening the suspicious file for reading
    FILE * suspectFile = fopen(fileName, "r");
    if (suspectFile == NULL) {
        printf("Opening suspectFile error\n");
        //exit(1);
    }

    // Get the size of the suspicious file
    fseek(suspectFile, 0, SEEK_END); // get the cursor to the end of the file
    lSize = ftell(suspectFile); // get the suspicious file size
    rewind(suspectFile); // move cursor to beginning?

    // allocate memory for the suspicious file
    unsigned char * suspectPtr = (unsigned char*) malloc(lSize);
    if (suspectPtr == NULL) {
        printf("Memory allocation for suspectPtr error\n");
    }

    // read the suspicious file to memory
    res = fread(suspectPtr, 1, lSize, suspectFile);
    if (res != lSize) {
        printf("Reading from suspectFile error\n");
    }

    printf("Checking for EVP_SealInit\n");
    if (containsCode(suspectPtr, sealInitSignature, lSize)) { // has EVP_SealInit code
          printf("detected EVP_SealInit\n");
          // Check if EVP_OpenInit code doesn't exists
          FILE * openInitFile;
          unsigned char openInitSignature[_signaturesScanSize];

          openInitFile = fopen("/etc/openinit_sig", "r");
          if (openInitFile == NULL) {
            printf("Opening openInitFile error\n");
            //exit(1);
          }

          res = fread(openInitSignature, 1, _signaturesScanSize, openInitFile);
          if (res != _signaturesScanSize) {
              printf("Reading from openInitFile error\n");
          }

          printf("Checking openInitSignature\n");
          // Check if NOT containing EVP_OpenInit
          if (!containsCode(suspectPtr, openInitSignature, lSize)) {
              printf("EVP_OpenInit NOT detected\n");
              // doesn't have EVP_OpenInit code - We have a suspect, prevent it from
              // entering the system.
            isMalicious = true;
          } else {
            printf("detected EVP_OpenInit\n");
          }

          fclose(openInitFile);
    }

    free(suspectPtr);


    return isMalicious;
}
