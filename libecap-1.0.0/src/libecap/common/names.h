/* (C) 2008 The Measurement Factory */

#ifndef LIBECAP__COMMON_NAMES_H
#define LIBECAP__COMMON_NAMES_H

#include <libecap/common/name.h>

namespace libecap {

// various protocol elements for use with libecap::Name

extern const Name protocolHttp;
extern const Name protocolHttps;
extern const Name protocolFtp;
extern const Name protocolGopher;
extern const Name protocolWais;
extern const Name protocolUrn;
extern const Name protocolWhois;

extern const Name methodGet;
extern const Name methodPut;
extern const Name methodPost;
extern const Name methodHead;
extern const Name methodConnect;
extern const Name methodOptions;
extern const Name methodDelete;
extern const Name methodTrace;

extern const Name headerContentLength;
extern const Name headerTransferEncoding;
extern const Name headerReferer;
extern const Name headerVia;
extern const Name headerXClientIp;
extern const Name headerXServerIp;

// commonly used meta-information names, based on popular ICAP extensions
extern const Name metaClientIp;
extern const Name metaServerIp;
extern const Name metaUserName;
extern const Name metaAuthenticatedUser;
extern const Name metaAuthenticatedGroups;
extern const Name metaSubscriberId;
extern const Name metaVirusId;
extern const Name metaResponseInfo;
extern const Name metaResponseDesc;
extern const Name metaNextServices;

} // namespace libecap

#endif
