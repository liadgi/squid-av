#include <libecap/common/message.h>
#include <libecap/common/errors.h>

void libecap::Message::addTrailer() {
	// no trailer support by default
	Must(!"missing libecap::Message::addTrailer() implementation");
}
