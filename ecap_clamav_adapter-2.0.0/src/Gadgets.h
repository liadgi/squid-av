/* eCAP ClamAV Adapter                                http://www.e-cap.org/
 * Copyright (C) 2011 The Measurement Factory.
 * Distributed under GPL v2 without any warranty.                        */

#ifndef ECAP_CLAMAV_ADAPTER_GADGETS_H
#define ECAP_CLAMAV_ADAPTER_GADGETS_H

#include <string>
#include <limits>

class Time;

namespace Adapter {

// Parse a named "number of bytes" option, returning Size. Throw on errors.
// Negative values are treated as errors.
Size StringToSize(const std::string &value, const std::string &name);

// StringToSize(value, name) that returns sizeIfNone for "none" values.
Size StringToSize(const std::string &value, const std::string &name, const Size sizeIfNone);

// Parse a named "seconds" option, returning Time. Throw on errors.
// Fractional seconds are accepted. Negative values are treated as errors.
Time StringToTime(const std::string &value, const std::string &name);

// return either (augend + addend) or, on overflows, the maximum possible value
inline Size SafeAdd(const Size augend, const Size addend)
{
    const bool overflow = augend > (std::numeric_limits<Size>::max() - addend);
    return overflow ? std::numeric_limits<Size>::max() : (augend + addend);
}

} // namespace Adapter

#endif
