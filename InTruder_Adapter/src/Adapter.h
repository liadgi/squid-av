/* eCAP ClamAV Adapter                                http://www.e-cap.org/
 * Copyright (C) 2011 The Measurement Factory.
 * Distributed under GPL v2 without any warranty.                        */

#ifndef ECAP_CLAMAV_ADAPTER_H
#define ECAP_CLAMAV_ADAPTER_H

// this file should be included first from all adapter sources

#ifdef HAVE_CONFIG_H
#include "autoconf.h"
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include <libecap/common/forward.h>

namespace Adapter {

    class Answers;
    class Cfgtor;
    class FileBuffer;
    class Service;
    class Timeout;
    class TricklingConfig;
    class Xaction;

}

typedef uint64_t Size; // size of anything potentially larger than one malloc()

#endif /* ECAP_CLAMAV_ADAPTER_H */
