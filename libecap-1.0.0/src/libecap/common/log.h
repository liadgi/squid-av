/* (C) 2008  The Measurement Factory */

#ifndef LIBECAP__COMMON__LOG_H
#define LIBECAP__COMMON__LOG_H

#include <libecap/common/libecap.h>

namespace libecap {

// constants to form log verbosity mask below
enum ImportanceLevel { ilDebug = 0, ilNormal = 1, ilCritical = 2 }; // 0xF
enum FrequencyLevel { flOperation = 0, flXaction = 1 << 4, flApplication = 2 << 4}; // 0xF0
enum MessageSizeLevel { mslNormal = 0, mslLarge = 1 << 8 }; // 0xF00

// maintains a mask that determines how verbose the log entry should be
class LogVerbosity {
	public:
		typedef unsigned int Mask;
		LogVerbosity(Mask aMask): mask(aMask) {}

		bool critical() const { return (mask & 0xF) == ilCritical; }
		bool normal() const { return (mask & 0xF) == ilNormal; }
		bool debugging() const { return (mask & 0xF) == ilDebug; }

		bool operation() const { return (mask & 0xF0) == flOperation; }
		bool xaction() const { return (mask & 0xF0) == flXaction; }
		bool application() const { return (mask & 0xF0) == flApplication; }

		bool small() const { return (mask & 0xF00) == mslNormal; }
		bool large() const { return (mask & 0xF00) == mslLarge; }

private:
		Mask mask;
};

} // namespace libecap

#endif
