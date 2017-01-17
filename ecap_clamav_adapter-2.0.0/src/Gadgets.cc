/* eCAP ClamAV Adapter                                http://www.e-cap.org/
 * Copyright (C) 2011 The Measurement Factory.
 * Distributed under GPL v2 without any warranty.                        */

#include "Adapter.h"
#include "Gadgets.h"
#include "Time.h"
#include <libecap/common/errors.h>

#include <sstream>


Size Adapter::StringToSize(const std::string &value, const std::string &name)
{
    std::istringstream input(value);
    Size size;
    if (input >> size && input.eof())
        return size;

    throw TextExceptionHere("invalid " + name + " value: " + value);
}

Size Adapter::StringToSize(const std::string &value, const std::string &name, const Size sizeIfNone)
{
    return value == "none" ? sizeIfNone : StringToSize(value, name);
}


Time Adapter::StringToTime(const std::string &value, const std::string &name)
{
    std::istringstream input(value);
    double configuredSeconds;
    if (input >> configuredSeconds && input.eof()) {
        if (configuredSeconds >= 0 && configuredSeconds < static_cast<double>(std::numeric_limits<time_t>::max())) {
            const time_t roundedSeconds = static_cast<time_t>(configuredSeconds);
            const double fraction = configuredSeconds-roundedSeconds;
            const int usec = std::max(0, static_cast<int>(1e6*fraction));
            return Time(roundedSeconds, usec);
        }
    }

    throw TextExceptionHere("invalid " + name + " value: " + value);
}
