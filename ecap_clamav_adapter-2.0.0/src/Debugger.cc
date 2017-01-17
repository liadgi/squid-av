/* eCAP ClamAV Adapter                                http://www.e-cap.org/
 * Copyright (C) 2011 The Measurement Factory.
 * Distributed under GPL v2 without any warranty.                        */

#include "Adapter.h"
#include "Debugger.h"
#include "Time.h"
#include <libecap/common/registry.h>
#include <libecap/host/host.h>
#include <iostream>

// TODO: support automated prefixing of log messages

Debugger::Debugger(const libecap::LogVerbosity lv):
    debug(libecap::MyHost().openDebug(lv)), fillChar(' ')
{
}

Debugger::~Debugger()
{
    if (debug)
        libecap::MyHost().closeDebug(debug);
}

void Debugger::storeFormat()
{
    if (debug) {
        fillChar = debug->fill();
        flags = debug->flags();
    }
}

void Debugger::restoreFormat()
{
    if (debug) {
        debug->flags(flags);
        debug->fill(fillChar);
    }
}

Debugger &Debugger::operator <<(const Time &time)
{
    if (debug) {
        *debug << time.tv_sec << '.';
        if (time.tv_usec) {
            storeFormat();
            debug->fill('0');
            debug->width(6);
            *debug << time.tv_usec; // TODO: do not print trailing zeros
            restoreFormat();
        } else {
            *debug << '0';
        }
    }
    return *this;
}
