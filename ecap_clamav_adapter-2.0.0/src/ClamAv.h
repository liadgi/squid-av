/* eCAP ClamAV Adapter                                http://www.e-cap.org/
 * Copyright (C) 2011 The Measurement Factory.
 * Distributed under GPL v2 without any warranty.                        */

#ifndef ECAP_ADAPTER_CLAMAV_WRAPPER
#define ECAP_ADAPTER_CLAMAV_WRAPPER

#include <string>
#include "Antivirus.h"

namespace Adapter {

// libClamAV wrapper using Antivirus API
class ClamAv: public Antivirus
{
public:
    ClamAv();
    virtual ~ClamAv();

    /* Antivirus API */
    virtual void configure(const Options &cfg);
    virtual void reconfigure(const Options &cfg);
    virtual void update();

private:
    /* Antivirus API */
    virtual void scan(Answer &answer);

    void close();
};

} // namespace Adapter

#endif
