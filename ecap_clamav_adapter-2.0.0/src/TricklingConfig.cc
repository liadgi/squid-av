/* eCAP ClamAV Adapter                                http://www.e-cap.org/
 * Copyright (C) 2011 The Measurement Factory.
 * Distributed under GPL v2 without any warranty.                        */

#include "Adapter.h"
#include <limits>
#include "TricklingConfig.h"

Adapter::TricklingConfig::TricklingConfig():
    startDelay(Time(1, 0)),
    period(Time(10, 0)),
    dropSize(0),
    sizeMax(std::numeric_limits<Size>::max())
{
}

bool Adapter::TricklingConfig::changedSubstantially(const TricklingConfig &old) const
{
    // Would keepTrickling() produce a different result with the current config?
    // If yes, should we reconfigure now?

    // dropSize change does not affect drop deadlines or trickling duration

    // longer startDelay or period means the current Timeout may fire too soon, but we
    // are not going to save any resources if we reconfigure now (and may lose some!)

    return
        // with a shorter delay, we may start trickling sooner
        this->startDelay < old.startDelay ||
        // with a shorter period, we may trickle the next drop sooner
        this->period < old.period ||
        // with a smaller limit, we may stop trickling sooner
        this->sizeMax < old.sizeMax;
}
