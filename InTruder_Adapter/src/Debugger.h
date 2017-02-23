/* eCAP ClamAV Adapter                                http://www.e-cap.org/
 * Copyright (C) 2011 The Measurement Factory.
 * Distributed under GPL v2 without any warranty.                        */

#ifndef ECAP_CLAMAV_ADAPTER_DEBUGGER_H
#define ECAP_CLAMAV_ADAPTER_DEBUGGER_H

#include <libecap/common/log.h>
#include <ios>

using libecap::ilDebug;
using libecap::ilNormal;
using libecap::ilCritical;
using libecap::flOperation;
using libecap::flXaction;
using libecap::flApplication;
using libecap::mslLarge;

class Time;

// TODO: rename to Log

// libecap::host::openDebug/closeDebug calls wrapper for safety and convenience
class Debugger
{
public:
    explicit Debugger(const libecap::LogVerbosity lv); // opens
    ~Debugger(); // closes

    // logs a message if host enabled debugging at the specified level
    template <class T>
    Debugger &operator <<(const T &msg)
    {
        if (debug)
            *debug << msg;
        return *this;
    }

    // specialized Time logging
    Debugger &operator <<(const Time &time);

    /* store/restore debugging stream format before/after changing it */
    void storeFormat();
    void restoreFormat();

private:
    /* prohibited and not implemented */
    Debugger(const Debugger &);
    Debugger &operator=(const Debugger &);

    std::ostream *debug; // host-provided debug ostream or nil

    /* debugging stream format stored by storeFormat() */
    std::ios_base::fmtflags flags;
    char fillChar;
};

// use this for low-level debugging messages where you cannot use DebugFun()
#define DebugHere(logVerbosity) \
    Debugger(logVerbosity) << __FILE__ << ':' << __LINE__ << ':' << ' '

// use this for low-level debugging messages in all functions and methods
#define DebugFun(logVerbosity) \
    DebugHere(logVerbosity) << __FUNCTION__ << '(' << ')' << ' '

#endif
