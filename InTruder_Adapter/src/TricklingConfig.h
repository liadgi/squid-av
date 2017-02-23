/* eCAP ClamAV Adapter                                http://www.e-cap.org/
 * Copyright (C) 2011 The Measurement Factory.
 * Distributed under GPL v2 without any warranty.                        */

#ifndef ECAP_CLAMAV_ADAPTER_TRICKLING_CONFIG_H
#define ECAP_CLAMAV_ADAPTER_TRICKLING_CONFIG_H

#include "Time.h"

namespace Adapter {

// manages body trickling algorithm configuration
class TricklingConfig
{
public:
    TricklingConfig(); // sets default configuration values

    // whether it is worth reconfiguring all currently trickling transactions now
    bool changedSubstantially(const TricklingConfig &old) const;

    Time startDelay; // wait that long before the first drop
    Time period; // time between drops
    Size dropSize; // maximum size of a drop
    Size sizeMax; // do not trickle more body bytes
};

}

#endif
