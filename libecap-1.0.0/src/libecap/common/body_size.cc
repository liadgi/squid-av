#include <libecap/common/body_size.h>
#include <libecap/common/errors.h>

libecap::BodySize::size_type libecap::BodySize::badSize() const {
	Must(!"attempt to use unknown libecap::BodySize size"); // always throw
	return 0; // not reached
}
