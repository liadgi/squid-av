#include <libecap/common/names.h>

const libecap::Name libecap::protocolHttp("HTTP", libecap::Name::NextId());
const libecap::Name libecap::protocolHttps("HTTPS", libecap::Name::NextId());
const libecap::Name libecap::protocolFtp("FTP", libecap::Name::NextId());
const libecap::Name libecap::protocolGopher("GOPHER", libecap::Name::NextId());
const libecap::Name libecap::protocolWais("WAIS", libecap::Name::NextId());
const libecap::Name libecap::protocolUrn("URN", libecap::Name::NextId());
const libecap::Name libecap::protocolWhois("WHOIS", libecap::Name::NextId());

const libecap::Name libecap::methodGet("GET", libecap::Name::NextId());
const libecap::Name libecap::methodPut("PUT", libecap::Name::NextId());
const libecap::Name libecap::methodPost("POST", libecap::Name::NextId());
const libecap::Name libecap::methodHead("HEAD", libecap::Name::NextId());
const libecap::Name libecap::methodConnect("CONNECT", libecap::Name::NextId());
const libecap::Name libecap::methodOptions("OPTIONS", libecap::Name::NextId());
const libecap::Name libecap::methodDelete("DELETE", libecap::Name::NextId());
const libecap::Name libecap::methodTrace("TRACE", libecap::Name::NextId());

const libecap::Name libecap::headerContentLength("Content-Length", libecap::Name::NextId());
const libecap::Name libecap::headerTransferEncoding("Transfer-Encoding", libecap::Name::NextId());
const libecap::Name libecap::headerReferer("Referer", libecap::Name::NextId());
const libecap::Name libecap::headerVia("Via", libecap::Name::NextId());
const libecap::Name libecap::headerXClientIp("X-Client-IP", libecap::Name::NextId());
const libecap::Name libecap::headerXServerIp("X-Server-IP", libecap::Name::NextId());

const libecap::Name libecap::metaClientIp = headerXClientIp;
const libecap::Name libecap::metaServerIp = headerXServerIp;
const libecap::Name libecap::metaUserName("X-Client-Username", libecap::Name::NextId());
const libecap::Name libecap::metaAuthenticatedUser("X-Authenticated-User", libecap::Name::NextId());
const libecap::Name libecap::metaAuthenticatedGroups("X-Authenticated-Groups", libecap::Name::NextId());
const libecap::Name libecap::metaSubscriberId("X-Subscriber-ID", libecap::Name::NextId());
const libecap::Name libecap::metaVirusId("X-Virus-ID", libecap::Name::NextId());
const libecap::Name libecap::metaResponseInfo("X-Response-Info", libecap::Name::NextId());
const libecap::Name libecap::metaResponseDesc("X-Response-Desc", libecap::Name::NextId());
const libecap::Name libecap::metaNextServices("X-Next-Services", libecap::Name::NextId());
