/* eCAP ClamAV Adapter                                http://www.e-cap.org/
 * Copyright (C) 2011 The Measurement Factory.
 * Distributed under GPL v2 without any warranty.                        */

#ifndef ECAP_CLAMAV_ADAPTER_TIMEOUT_H
#define ECAP_CLAMAV_ADAPTER_TIMEOUT_H

#include "Pointers.h"
#include "Time.h"

namespace Adapter {

// Aggregates data to control the wait limit of transaction.
// Service creates, owns, and destroys Timeout objects.
// Xaction stores an opaque active() timeout pointer
//   in lieu of the Service timeout queue reservation confirmation or handler.
class Timeout
{
public:
    explicit Timeout(const XactionPointer &anX):
        xaction_(anX) {}

    // whether there is a transaction waiting for this timeout
    bool active() const { return !xaction_.expired(); }

    SharedXactionPointer xaction() { return SharedXactionPointer(xaction_); }

    // forget about transaction (e.g., after the scan answer is received)
    void deactivate() { xaction_.reset(); }

    Time deadline; // when to notify the transaction about the timeout

private:
    XactionPointer xaction_;
};

} // namespace Adapter

#endif // ECAP_CLAMAV_ADAPTER_TIMEOUT_H
