/* eCAP ClamAV Adapter                                http://www.e-cap.org/
 * Copyright (C) 2011 The Measurement Factory.
 * Distributed under GPL v2 without any warranty.                        */

#include "Adapter.h"
#include "Answer.h"
#include "Answers.h"
#include "Service.h"
#include "Timeout.h"
#include "TricklingConfig.h"
#include "Xaction.h"
#include "ClamAv.h"
#include "FileBuffer.h"
#include "Debugger.h"
#include "Gadgets.h"

#include <libecap/common/errors.h>
#include <libecap/common/named_values.h>

#include <stdlib.h>
#include <iostream>
#include <iomanip>
#include <limits>
#include <sstream>
#include <cstring>
#include <cstdio>


static const time_t timeNone = static_cast<time_t>(-1);

// Time between antivirus database update checks
// Is it better to update externally instead?
//    Yes, but would external updates affect existing engine??
// 0 = on every access; timeNone = never
const time_t dbUpdateGap = 60; // in seconds

// default staging filename template
static const std::string TmpFileNameTemplateDefault =
    "/tmp/eclamavXXXXXX"; // TODO: use $TEMP


static
bool cmpTimeoutPointers(const Adapter::Timeout *a, const Adapter::Timeout *b)
{
    // Timeouts::top() uses us as a "<" operator and returns the largest object;
    // reverse the comparison so that top() returns the smallest/nearest Timeout
    return a->deadline > b->deadline;
}

Size Adapter::Service::MaxSize()
{
    // FileBuffer cannot read() messages exceeding off_t limits.
    // We cannot handle sizes exceeding Size limits.
    // Comparing Size with off_t is tricky because only off_t is signed.
    // TODO: Just use std::make_unsigned when we switch to C++11.
    return sizeof(Size) < sizeof(off_t) ?
           std::numeric_limits<Size>::max() :
           std::min(std::numeric_limits<Size>::max(),
        static_cast<Size>(std::numeric_limits<off_t>::max()));
}

Adapter::Service::Service(const std::string &aMode):
    mode(aMode),
    blockOnError(false),
    scanAsynchronously(AllowAsyncScans()),
    answers(0),
    xactions(new Xactions),
    timeouts(0),
    tricklingConfig_(0),
    vbAccumulationMax_(MaxSize()),
    lastDbUpdate(0),
    reconfiguring(false)
{
    if (AllowAsyncScans()) {
        answers = new Answers;
        timeouts = new Timeouts(&cmpTimeoutPointers);
    }
}

Adapter::Service::~Service()
{
    if (answers)
        answers->abandon();

    delete xactions;
    delete timeouts;
    delete tricklingConfig_;
}

std::string Adapter::Service::uri() const
{
    return "ecap://e-cap.org/ecap/services/clamav?mode=" + mode;
}

std::string Adapter::Service::tag() const
{
    return PACKAGE_VERSION;
}

void Adapter::Service::describe(std::ostream &os) const
{
    os << PACKAGE_NAME << " v" << PACKAGE_VERSION;
}

// pthread support test (to avoid spreading ifdefs around the code)
bool Adapter::Service::AllowAsyncScans()
{
#ifdef HAVE_PTHREAD
    return true;
#else
    return false;
#endif
}

bool Adapter::Service::makesAsyncXactions() const
{
    if (scanAsynchronously)
        return true;

    // Our scanAsynchronously may become false during reconfiguration
    // while we still have pending asynchronous transactions and, hence,
    // still need the host to treat us as an async service. The first answers
    // user is this Service, so we only interested in higher user counts.
    return AllowAsyncScans() && answers && (answers->users() > 1);
}

Size Adapter::Service::vbAccumulationMax() const
{
    return std::min(vbAccumulationMax_, MaxSize());
}

namespace Adapter {
    class Cfgtor: public libecap::NamedValueVisitor
    {
    public:
        Cfgtor(Service &aSvc):
            svc(aSvc) {}
        virtual void visit(const libecap::Name &name, const libecap::Area &value)
        {
            svc.setOne(name, value);
        }
        Service &svc;
    };
} // namespace Adapter

void Adapter::Service::configure(const Options &cfg)
{
    // a workaround for host application that should have called reconfigure()
    if (scanner) {
        reconfigure(cfg);
        return;
    }

    setAll(cfg);

    // create an antivirus scanner; TODO: should some services share instances?
    Must(!scanner);
    scanner.reset(new ClamAv);
    scanner->configure(cfg);

    checkpoint();
}

// we may be called from configure() if a buggy host does not call us directly
void Adapter::Service::reconfigure(const Options &newCfg)
{
    reconfiguring = true;
    setAll(newCfg);
    Must(scanner);
    scanner->reconfigure(newCfg);
    checkpoint();
    reconfiguring = false;
}

void Adapter::Service::setAll(const Options &cfg)
{
    tmpFileNameTemplate = TmpFileNameTemplateDefault;

    // TODO: convert to std::unique_ptr when we require C++11.
    const std::auto_ptr<TricklingConfig> oldTricklingConfig(tricklingConfig_);
    tricklingConfig_ = new TricklingConfig();

    Cfgtor cfgtor(*this);
    cfg.visitEachOption(cfgtor);

    finalizeTricklingConfig(oldTricklingConfig);


    /* checks */

    checkStagingDir();

    if (!vbAccumulationMax_) {
        Debugger(flApplication) << "Warning: message_size_max=0 allows all " <<
            "messages without analysis. Did you mean message_size_max=none?";
    }


    /* reporting */

    Debugger(ilDebug|flApplication) << "async=" << scanAsynchronously;

    if (vbAccumulationMax_ != MaxSize())
        Debugger(ilDebug|flApplication) << "message_size_max=" << vbAccumulationMax_;

    printTricklingConfig();

    Debugger(ilDebug|flApplication) << "internal_accumulation_max=" << MaxSize();
}

void Adapter::Service::printTricklingConfig() const
{
    if (!tricklingConfig_)
        return;

    Debugger debugger(ilDebug|flApplication);
    debugger <<
        "trickling_start_delay=" << tricklingConfig_->startDelay << "\n" <<
        "trickling_period=" << tricklingConfig_->period << "\n" <<
        "trickling_drop_size=" << tricklingConfig_->dropSize << "\n";

    if (tricklingConfig_->sizeMax != MaxSize())
        debugger << "trickling_size_max=" << tricklingConfig_->sizeMax;
}

void Adapter::Service::setOne(const libecap::Name &name, const libecap::Area &valArea)
{
    const std::string value = valArea.toString();
    if (name == "on_error")
        setOnError(value);
    else
    if (name == "staging_dir")
        setTmpDir(value);
    else
    if (name == "huge_size") {
        // TODO: Remove in the next release.
        Debugger(ilCritical|flApplication) << "huge_size is no longer supported " <<
            "and may be misinterpreted. Use message_size_max instead.";
        vbAccumulationMax_ = StringToSize(value, name.image(), MaxSize());
    } else
    if (name == "message_size_max")
        vbAccumulationMax_ = StringToSize(value, name.image(), MaxSize());
    else
    if (name == "debug")
        ; // the scanner handles that (TODO: ask the scanner instead)
    else
    if (name == "async")
        setAsyncScans(value);
    else
    if (name == "trickling_period")
        tricklingConfig().period = StringToTime(value, name.image());
    else
    if (name == "trickling_drop_size")
        tricklingConfig().dropSize = StringToSize(value, name.image());
    else
    if (name == "trickling_start_delay")
        tricklingConfig().startDelay = StringToTime(value, name.image());
    else
    if (name == "trickling_size_max")
        tricklingConfig().sizeMax = StringToSize(value, name.image(), MaxSize());
    else
    if (name.assignedHostId())
        ; // skip host-specific options
    else
        throw libecap::TextException("eClamAV: "
            "unsupported adapter configuration parameter: " + name.image());
}

void Adapter::Service::setOnError(const std::string &value)
{
    // default is not to block
    if (value == "block")
        blockOnError = true;
    else
    if (value == "allow")
        blockOnError = false;
    else
        throw libecap::TextException("eClamAV: unsupported on_error config "
            "value (" + uri() + "): " + value);
}

void Adapter::Service::setTmpDir(const std::string &prefix)
{
    std::string temp = prefix;
    if (temp.empty() || temp == "default")
        temp = TmpFileNameTemplateDefault;
    if (temp.rfind('X') != temp.size()-1)
        temp += "XXXXXX";
    tmpFileNameTemplate = temp;
}

void Adapter::Service::checkStagingDir()
{
    const FileBuffer file(tmpFileNameTemplate); // may throw
    // will close and remove the temporary file on destruction
}

void Adapter::Service::setAsyncScans(const std::string &value)
{
    if (value == "no") {
        scanAsynchronously = false;
    } else
    if (value == "yes") {
        if (!AllowAsyncScans()) {
            const std::string msg = "Cannot honor async=yes "
                "without POSIX threads (pthreads) support.";
            throw libecap::TextException(msg);
        }
        scanAsynchronously = true;
    } else {
        const std::string msg = "Unsupported value in async=" +
            value + ". Expected 'yes' or 'no' value.";
        throw libecap::TextException(msg);
    }
}

void Adapter::Service::start()
{
    Must(tmpFileNameTemplate.size() > 0); // we were successfully configured
    libecap::adapter::Service::start();
}

void Adapter::Service::stop()
{
    libecap::adapter::Service::stop();
}

void Adapter::Service::retire()
{
    libecap::adapter::Service::retire();
}

bool Adapter::Service::wantsUrl(const char *) const
{
    return true; // no-op is applied to all messages
}

Adapter::Service::MadeXactionPointer
Adapter::Service::makeXaction(libecap::host::Xaction *hostx)
{
    checkpoint();
    const libecap::shared_ptr<Service> s = std::tr1::static_pointer_cast<Service>(self);
    SharedXactionPointer x(new Xaction(s, hostx));
    x->self = x;
    x->serviceRegistration = new Xactions::iterator(xactions->insert(xactions->end(), x));
    return x;
}

void Adapter::Service::deregisterXaction(Xaction &xaction) const
{
    Xactions::iterator * &it = xaction.serviceRegistration;
    Must(it);
    xactions->erase(*it);
    delete it;
    it = 0;
}

Adapter::Timeout *Adapter::Service::wakeMeUpToTrickle(const XactionPointer &xaction, const Time &delay) const
{
    DebugFun(flXaction) << "wake up " << xaction.lock() << " after " << delay;

    Timeout *timeout = new Timeout(xaction);
    timeout->deadline = Time::Now();
    timeout->deadline += delay;
    Must(timeout->active());

    Must(timeouts);
    timeouts->push(timeout);
    return timeout;
}

void Adapter::Service::cancelTimeout(Adapter::Timeout *timeout) const
{
    Must(timeout);
    // finding a specific timeout object in the deadline-ordered queue is too
    // slow, so we just mark the timeout object to ignore it when we reach it
    timeout->deactivate();
    Must(!timeout->active());
}

Adapter::TricklingConfig &
Adapter::Service::tricklingConfig()
{
    Must(tricklingConfig_);
    return *tricklingConfig_;
}

void Adapter::Service::finalizeTricklingConfig(const std::auto_ptr<TricklingConfig> &oldConfig)
{
    if (!tricklingConfig_->dropSize) {
        // TODO: Warn if at least one other trickling option was explicitly configured.
        delete tricklingConfig_;
        tricklingConfig_ = 0;
    }

    if (oldConfig.get() && tricklingConfig_ &&
        !tricklingConfig_->changedSubstantially(*oldConfig))
        return;

    for (Xactions::iterator it = xactions->begin(); it != xactions->end(); ++it) {
        // Transactions must call deregisterXaction() before disappearing
        // because we cannot [efficiently] limit xaction_ growth otherwise.
        // Thus, xactions must not contain expired pointers.
        const SharedXactionPointer xaction(*it); // throws if *it has expired
        xaction->reconfigure();
    }
}

bool Adapter::Service::canWait(Time &waitTime) const
{
    // only called for async services
    Must(answers);
    Must(timeouts);

    if (!answers->empty())
        return false; // no time to wait: a scan answer is available already

    const Time maxWait(0, 300*1000);
    if (timeouts->empty()) {
        waitTime = maxWait;
    } else {
        const Timeout *earliestTimeout = timeouts->top();
        Must(earliestTimeout);

        const Time now = Time::Now();
        if (earliestTimeout->deadline <= now)
            return false; // no time to wait: a scan timed out already

        waitTime = std::min(earliestTimeout->deadline - now, maxWait);
    }

    return true;
}

void Adapter::Service::suspend(timeval & timeout)
{
    Time myWait;
    if (canWait(myWait)) {
        if (myWait < timeout)
            timeout = myWait;
    } else {
        timeout = Time::Zero();
    }
}

void Adapter::Service::resume()
{
    Must(answers);
    Must(timeouts);

    while (Answer *answer = answers->get()) {
        if (MyAnswer *ma = dynamic_cast<MyAnswer *>(answer)) {
            if (const SharedXactionPointer x = ma->xaction.lock())
                x->tellHostToResume(answer);
            else
                delete ma; // the transaction finished before we got the answer
        } else {
            Debugger(ilCritical|flXaction) << "internal error: " <<
                "Adapter::Service::resume() got wrong scan answer object: " <<
                answer->fileName << ".";
            delete answer;
        }
    }

    if (!timeouts->empty())
        notifyTimeouts();
}

void Adapter::Service::checkpoint()
{
    if (dbUpdateGap == timeNone)
        return; // no updates configured

    if (time(0) < lastDbUpdate + dbUpdateGap)
        scanner->update();

    // we enforce the time gap _between_ updates so that even relatively long
    // updates do not lead to gap-free uptates
    lastDbUpdate = time(0);
}

// helper for notifyTimeouts()
template <class Container>
inline
void deleteTop_(Container &container)
{
    delete container.top();
    container.pop();
}

// notify all timed out transactions, if any
void Adapter::Service::notifyTimeouts()
{
    const Time now = Time::Now(); // once for the entire timeouts loop
    DebugFun(flOperation) << "candidates: " << timeouts->size();
    while (!timeouts->empty()) {
        Timeout * const candidate = timeouts->top();
        Must(candidate);

        if (!candidate->active()) {
            deleteTop_(*timeouts);
            continue;
        }

        const SharedXactionPointer xaction = candidate->xaction();
        if (!xaction->active()) {
            deleteTop_(*timeouts);
            continue;
        }

        // if the top candidate has not timed out yet, then none timed out
        // because top() always returns the item with the earliest deadline
        if (now < candidate->deadline) {
            DebugFun(flOperation) << "TTL: " << (candidate->deadline - now);
            break;
        }

        // the candidate transaction has timed out
        deleteTop_(*timeouts);
        xaction->tellHostToResume(0);
    }
    DebugFun(flOperation) << "remaining: " << timeouts->size();
}
