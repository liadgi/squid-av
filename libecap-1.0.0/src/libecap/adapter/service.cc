#include <libecap/adapter/service.h>
#include <libecap/common/errors.h>

// only services making async transactions need to override this
void libecap::adapter::Service::suspend(timeval &) {
	Must(!"async eCAP adapter Service is missing suspend()");
}

// only services making async transactions need to override this
void libecap::adapter::Service::resume() {
	Must(!"async eCAP adapter Service is missing resume()");
}
