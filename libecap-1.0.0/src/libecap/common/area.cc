#include <libecap/common/area.h>
#include <iostream>

namespace libecap {

struct StdStringAreaDetails: public AreaDetails {
	StdStringAreaDetails(const std::string &owner): owner_(owner) {}
	const std::string owner_;
};

} // namespace libecap

const libecap::size_type libecap::nsize = -1;


libecap::Area libecap::Area::FromTempString(const std::string &tmp) {
	shared_ptr<StdStringAreaDetails> details(new StdStringAreaDetails(tmp));
	return Area(details->owner_.data(), details->owner_.size(), details);
}

libecap::Area libecap::Area::FromTempBuffer(const char *start, libecap::size_type size) {
	return FromTempString(std::string(start, size));
}

std::string libecap::Area::toString() const {
	return std::string(start, size);
}

std::ostream &libecap::operator <<(std::ostream &os, const Area &area) {
	os.write(area.start, area.size);
	return os;
}
