/* eCAP ClamAV Adapter                                http://www.e-cap.org/
 * Copyright (C) 2011 The Measurement Factory.
 * Distributed under GPL v2 without any warranty.                        */

#include "Adapter.h"
#include "Answer.h"
#include "ClamAv.h"
#include "Debugger.h"
#include <iostream>

#include <libecap/common/name.h>
#include <libecap/common/area.h>
#include <libecap/common/options.h>
#include <cstring>
#include <string>
#include <stdexcept>

static const libecap::Name optDebug("debug");

inline void Throw(const char *message, const char *reason = "")
{
    std::string error(message);
    error += reason;
    error += "\n";
    throw std::runtime_error(error);
}

Adapter::ClamAv::ClamAv()
{
   
}

Adapter::ClamAv::~ClamAv()
{
    close();
}

void Adapter::ClamAv::scan(Answer &answer)
{
    // We assume that cl_*() functions used here are threadsafe.
/*
    const char *virname = 0;
    //const int eScanResult = cl_scanfile(answer.fileName.c_str(), &virname, 0, engine, CL_SCAN_STDOPT);

    switch (eScanResult) {
    case CL_CLEAN:
        answer.statusCode = Answer::scClean;
        break;

    case CL_VIRUS:
        answer.statusCode = Answer::scVirus;
        answer.virusName = virname;
        break;

    default:
        answer.statusCode = Answer::scError;
        //answer.errorMsg = cl_strerror(eScanResult);
    }
    */
}

void Adapter::ClamAv::configure(const Options &cfg)
{
}

void Adapter::ClamAv::reconfigure(const Options &cfg)
{

}



void Adapter::ClamAv::update()
{

}


void Adapter::ClamAv::close()
{

}
