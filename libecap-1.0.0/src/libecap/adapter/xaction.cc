#include <libecap/adapter/xaction.h>
#include <libecap/common/errors.h>

// only adapters that implement async Services need to override this method
void libecap::adapter::Xaction::resume() {
	Must(!"async eCAP adapter Xaction is missing resume()");
}
