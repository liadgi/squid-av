/* eCAP ClamAV Adapter                                http://www.e-cap.org/
 * Copyright (C) 2011 The Measurement Factory.
 * Distributed under GPL v2 without any warranty.                        */

#ifndef ECAP_CLAMAV_ADAPTER_ANSWER_H
#define ECAP_CLAMAV_ADAPTER_ANSWER_H

#include <string>


namespace Adapter {

// the result of scanning for a virus
// For now, the API is specific to scanners looking at files
class Answer
{
public:
    // summary of the scan status
    typedef enum {
        scUnknown, // scan has not started or has not finished
        scClean, // scan found nothing
        scVirus, // scan found a virus; see virusName
        scError // scan failed; see errorMsg
    } StatusCode;

    explicit Answer(const std::string &aFileName):
        fileName(aFileName),
        statusCode(scUnknown)
    {}

    virtual ~Answer() {}

    // send this answer, possibly asynchronously, to the requester
    virtual void deliver() = 0;

    const std::string fileName; // file to scan

    /* results of the scan */
    std::string virusName; // for scVirus
    std::string errorMsg; // for scError
    StatusCode statusCode; // overall outcome
};

} // namespace Adapter

#endif // ECAP_CLAMAV_ADAPTER_ANSWER_H
