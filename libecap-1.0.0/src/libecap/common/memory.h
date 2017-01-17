/* (C) 2008 The Measurement Factory */

#ifndef LIBECAP__COMMON_MEMORY_H
#define LIBECAP__COMMON_MEMORY_H

#include <libecap/common/libecap.h>
#include <tr1/memory>

// TODO: add support for boost pointers if std::tr1 is not available

namespace libecap {

using std::tr1::weak_ptr;
using std::tr1::shared_ptr;

} // namespace libecap

#endif
