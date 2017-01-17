/* eCAP ClamAV Adapter                                http://www.e-cap.org/
 * Copyright (C) 2011 The Measurement Factory.
 * Distributed under GPL v2 without any warranty.                        */

#include "Adapter.h"

#include <cerrno>
#include <cstring>
#include <string>
#include <limits>

#include <libecap/common/errors.h>

#include "Time.h"


Time Time::Now()
{
    timeval now;
    if (gettimeofday(&now, 0) < 0) {
        const int errNo = errno; // save to avoid corrupting
        throw TextExceptionHere("eClamAV: gettimeofday(2) failure: " + std::string(strerror(errNo)));
    }
    return Time(now);
}

Time Time::Max()
{
    return Time(std::numeric_limits<time_t>::max(), 999999L);
}

Time & Time::operator +=(const Time &tm)
{
    tv_sec += tm.tv_sec;
    tv_usec += tm.tv_usec;

    if (tv_usec >= 1000000L) {
        tv_usec -= 1000000L;
        ++tv_sec;
    }

    return *this;
}

Time & Time::operator -=(const Time &tm)
{
    tv_sec -= tm.tv_sec;
    tv_usec -= tm.tv_usec;

    if (tv_usec < 0) {
        tv_usec += 1000000L;
        --tv_sec;
    }

    return *this;
}
