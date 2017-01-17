/* (C) 2008 The Measurement Factory */

#ifndef LIBECAP__COMMON__DELAY_H
#define LIBECAP__COMMON__DELAY_H

#include <libecap/common/forward.h>

namespace libecap {

// encapsulates processing delay information
class Delay {
	public:
		Delay():
			progress(-1) {}
		explicit Delay(const std::string &state_):
			state(state_), progress(-1) {}
		Delay(const std::string &state_, double progress_):
			state(state_), progress(progress_) {}

		bool knownState() const { return progress >= 0.0; }
		bool knownProgress() const { return state.size() > 0; }

		std::string state; // user-friendly state description or empty
		double progress; // completed work fraction in (0,1) range or negative
};

} // namespace libecap

#endif
