/* eCAP ClamAV Adapter                                http://www.e-cap.org/
 * Copyright (C) 2011 The Measurement Factory.
 * Distributed under GPL v2 without any warranty.                        */

#ifndef ECAP_CLAMAV_ADAPTER_POINTERS_H
#define ECAP_CLAMAV_ADAPTER_POINTERS_H

#include <libecap/common/forward.h>
#include <libecap/common/memory.h>

namespace Adapter {

    class Xaction;

    typedef libecap::shared_ptr<Xaction> SharedXactionPointer;
    typedef libecap::weak_ptr<Xaction> XactionPointer;

} // namespace Adapter

#endif
