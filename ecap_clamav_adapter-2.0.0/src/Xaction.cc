/* eCAP ClamAV Adapter                                http://www.e-cap.org/
 * Copyright (C) 2011 The Measurement Factory.
 * Distributed under GPL v2 without any warranty.                        */

#include "Adapter.h"
#include "Answers.h"
#include "FileBuffer.h"
#include "Xaction.h"
#include "Debugger.h"
#include "Gadgets.h"
#include "Service.h"
#include "TricklingConfig.h"
/* #include "Timeout.h" -- Timeout is an opaque data type for Xaction */

#include <libecap/common/registry.h>
#include <libecap/common/named_values.h>
#include <libecap/common/errors.h>

#include <algorithm>
#include <sstream>
#include <iomanip>
#include <limits>
#include <climits>
#include <cstring>
#include <cerrno>
#include <cassert>


// when host asks for a piece of adapted body, we do not read more than this
static const libecap::size_type abBufSizeMax(16*1024);

// logged actions
static const std::string actClean = "no viruses found";
static const std::string actVirus = "virus found";
static const std::string actErrorLate = "late adapter error";
static const std::string actErrorBlock = "blocking on virus check error";
static const std::string actErrorAllow = "allowing despite virus check error";
static const std::string actErrorSalvaged = "ignoring virus check error";
static const std::string actExamine = "virus check needed";
static const std::string actSkipped = "virus check skipped";


/* Adapter::MyAnswer */

Adapter::MyAnswer::MyAnswer(const std::string &aFileName, const XactionPointer &anX, Answers *allAnswers):
    Answer(aFileName),
    xaction(anX),
    answers(allAnswers)
{
    DebugFun(flXaction) << " for " << fileName << " with " << answers;

    if (answers)
        answers->use();
}

Adapter::MyAnswer::~MyAnswer()
{
    DebugFun(flXaction) << " for " << fileName;

    assert(!answers);
}

void Adapter::MyAnswer::deliver()
{
    if (Answers *myAnswers = answers) {
        answers = 0;
        myAnswers->put(this); // will delete this Answer, possibly immediately!
        myAnswers->abandon(); // may delete the Answers that "myAnswers" points to
    } else {
        // we are delivering the result of a blocking scan
        if (const SharedXactionPointer x = xaction.lock())
            x->onAnswer(*this);
        else
            delete this; // the transaction finished before we got the answer
    }
}


/* Adapter::Xaction */

#define EnterFailSafeMethod() \
    try { \
        DebugFun(flXaction) << "entering " << this

#define ExitFailSafeMethod() \
    } catch (const std::exception &e) { \
        handleError(e); \
    } \
    DebugFun(flXaction) << "exiting " << this


Adapter::Xaction::Xaction(libecap::shared_ptr<Service> aService,
    libecap::host::Xaction *aHostX):
    serviceRegistration(0),
    service(aService),
    hostx_(aHostX),
    timeout(0),
    answerToResumeWith(0),
    vbFile(0),
    abOffset(0),
    trickledSize(0),
    receivingVb(opUndecided),
    sendingAb(opUndecided),
    tricklingTriggers(ttReconfiguration),
    finalAction(actPending),
    vbComplete(false)
{
}

Adapter::Xaction::~Xaction()
{
    DebugFun(flXaction) << this << " hostx_=" << hostx_ << " timeout=" << timeout
        << " serviceRegistration=" << serviceRegistration;
    delete vbFile;
    delete answerToResumeWith;
    assert(!timeout); // we cannot be in the queue if we are being deleted
    assert(!serviceRegistration);
}

Size Adapter::Xaction::vbOffset() const
{
    return vbFile ? vbFile->size() : 0;
}

const libecap::Area Adapter::Xaction::option(const libecap::Name &name) const
{
    if (name == libecap::metaVirusId && !virusId.empty())
        return libecap::Area(virusId.data(), virusId.size());

    return libecap::Area();
}

void Adapter::Xaction::visitEachOption(libecap::NamedValueVisitor &visitor) const
{
    if (!virusId.empty())
        visitor.visit(libecap::metaVirusId,
            libecap::Area(virusId.data(), virusId.size()));
}

libecap::host::Xaction &Adapter::Xaction::hostx()
{
    Must(hostx_);
    return *hostx_;
}

// this method is used to make the last call to host transaction
// last call may delete adapter transaction if the host no longer needs it
libecap::host::Xaction &Adapter::Xaction::lastHostCall()
{
    libecap::host::Xaction &x = hostx();
    disconnect();
    return x;
}

void Adapter::Xaction::start()
{
    EnterFailSafeMethod();

    getUri();

    if (!shouldExamine()) {
        receivingVb = opNever;
        allowAccess();
        return;
    }

    trickledStamp = Time::Now();
    if (service->trickling())
        trickle();

    receivingVb = opRequested;
    hostx().vbMake(); // ask host to supply virgin body

    ExitFailSafeMethod();
}

bool Adapter::Xaction::shouldExamine()
{
    static const libecap::Name contentTypeName("Content-Type");
    libecap::shared_ptr<libecap::Message> adapted = hostx().virgin().clone();
    if (adapted->header().hasAny(contentTypeName)) {
        const libecap::Header::Value contentType = adapted->header().value(contentTypeName);
        
        std::string contentTypeType;                

        if (contentType.size > 0) {
                std::string contentTypeString = contentType.toString(); 
            
            if ((!strstr(contentTypeString.c_str(),"application/x-gzip")) &&
                (!strstr(contentTypeString.c_str(),"application/octet-stream"))) {
                debugAction("Not application/x-gzip or application/octet-stream packet");
                return false;
            } 
        }
    }

    if (!hostx().virgin().body()) {
        debugAction(actSkipped, "no body");
        return false;
    }

    const char *bodyCategory = syncBodySize();
    DebugFun(flXaction) << "body category: " << bodyCategory;
    if (!bodySize.known()) {
        debugAction(actExamine, bodyCategory);
        return true;
    }

    if (bodySize.value() == 0) {
        debugAction(actSkipped, "empty body");
        return false;
    }

    if (bodySize.value() > service->vbAccumulationMax()) {
        debugAction(actSkipped, "huge body");
        return false;
    }

    debugAction(actExamine, "acceptable body length");
    return true;
}

void Adapter::Xaction::resume()
{
    EnterFailSafeMethod();

    if (answerToResumeWith) {
        /* scan result */
        onAnswer(*answerToResumeWith);
        delete answerToResumeWith;
        answerToResumeWith = 0;
    } else {
        /* timeout */
        tricklingCheckpoint(ttTimeout);
    }

    ExitFailSafeMethod();
}

void Adapter::Xaction::stop()
{
    if (vbFile)
        close();
    disconnect();
    // we should be deleted soon
}

void Adapter::Xaction::disconnect()
{
    if (timeout) {
        service->cancelTimeout(timeout);
        timeout = 0;
    }

    if (serviceRegistration)
        service->deregisterXaction(*this);

    hostx_ = 0;
}

void Adapter::Xaction::abDiscard()
{
    Must(sendingAb == opRequested);
    sendingAb = opComplete; // host got everything it wanted; TODO: Add opRefused?

    // TODO: close and remove the file here instead of waiting for the dtor

    // we do not need more vb if the host is not interested in ab
    stopVb(false);
}

void Adapter::Xaction::abMake()
{
    Must(sendingAb == opRequested);
    sendingAb = opOn;
    abOffset = 0;
    if (vbFile)
        hostx().noteAbContentAvailable();
    // else no ab to offer yet; still waiting for noteVbContentAvailable()

    if (receivingVb == opComplete && !tricklingTriggers && sendingAb != opComplete) {
        sendingAb = opComplete;
        hostx().noteAbContentDone(vbComplete);
    }
}

void Adapter::Xaction::abMakeMore()
{
    // we cannot really make more than we already made
    Must(false && "cannot make more ab");
}

void Adapter::Xaction::abStopMaking()
{
    Must(sendingAb == opOn || sendingAb == opComplete);
    sendingAb = opComplete;

    // TODO: close and remove the file here instead of waiting for the dtor

    // we do not need more vb if the host is not interested in ab
    stopVb(false);
}

libecap::Area Adapter::Xaction::abContent(size_type offset, size_type size)
{
    Must(sendingAb == opOn || sendingAb == opComplete);

    // Bail if the host called us before we called noteAbContentAvailable(),
    // while we are still waiting for the first noteVbContentAvailable() call.
    if (!vbFile)
        return libecap::Area();

    Must(abOffset <= std::numeric_limits<Size>::max() - offset); // no overflows
    const Size pos = abOffset + offset;

    size_type bufSize = size;

    switch (finalAction) {
    case actPending: {
        // We are here because we are or were trickling. If we stopped trickling,
        // we should not give more than we had trickled (until the final action).
        const Size tricklingMax = (trickledSize > pos) ? trickledSize - pos : 0;
        bufSize = std::min(bufSize, tricklingMax);
        // fall through to also obey actAllow limits
    }

    case actAllow:
        // do not read more than abBufSizeMax at once
        bufSize = std::min(bufSize, abBufSizeMax);
        break;

    case actBlock:
        // do not give the host any more body bytes!
        bufSize = 0;
        break;
    }

    Must(pos <= Service::MaxSize()); // no off_t overflows
    return vbFile->read(pos, bufSize);
}

void Adapter::Xaction::abContentShift(size_type bytes)
{
    Must(sendingAb == opOn || sendingAb == opComplete);
    Must(abOffset <= std::numeric_limits<Size>::max() - bytes); // no overflows
    abOffset += bytes;
    // since we use a disk file, we do not shift its contents
}

void Adapter::Xaction::noteVbContentDone(bool atEnd)
{
    EnterFailSafeMethod();

    Must(receivingVb == opRequested || receivingVb == opOn);
    Must(vbFile && vbFile->isOpened());
    stopVb(atEnd);

    if (!vbOffset()) {
        debugAction(actSkipped, "empty body after all");
        allowAccess();
        return;
    }

    tricklingCheckpoint(ttVbContent);

    vbFile->flush();

    libecap::shared_ptr<Antivirus> scanner = service->scanner;
    Must(scanner);

    MyAnswer answer(vbFile->name(), self, 0 /* no queue */);
    scanner->blockingScan(answer);
       

    ExitFailSafeMethod();
}

void Adapter::Xaction::noteVbContentAvailable()
{
    EnterFailSafeMethod();

    Must(receivingVb == opRequested || receivingVb == opOn);
    receivingVb = opOn;

    // get all vb bytes that the host has buffered
    const libecap::Area vb = hostx().vbContent(0, libecap::nsize);

    if (vb.size > service->vbAccumulationMax() ||
        vbOffset() > service->vbAccumulationMax() - vb.size) {
        handleHuge("huge body after all");
        return;
    }

    if (!vbFile)
        open();

    vbFile->write(vb);

    // TODO: optimize to minimize shifting so that we can useVirgin more often
    hostx().vbContentShift(vb.size); // our write() writes everything or throws

    if (tricklingTriggers)
        tricklingCheckpoint(ttVbContent);
    else
    if (sendingAb == opOn)
        hostx().noteAbContentAvailable();
    else
        Must(sendingAb == opRequested); // we are not receiving in vain

    ExitFailSafeMethod();
}

void Adapter::Xaction::useVirgin()
{
    Must(sendingAb == opUndecided);
    sendingAb = opNever;

    Must(!vbOffset()); // cannot use vb if we consumed some of it already
    stopVb(false);

    lastHostCall().useVirgin();
}

void Adapter::Xaction::useStored()
{
    libecap::shared_ptr<libecap::Message> adapted = hostx().virgin().clone();
    Must(adapted != 0);

    Must(adapted->body());
    Must(sendingAb == opUndecided);
    sendingAb = opRequested;
    hostx().useAdapted(adapted); // will probably call our abMake
}

void Adapter::Xaction::prepFinalAction(const FinalAction action)
{
    Must(finalAction == actPending);
    Must(action != actPending);
    finalAction = action;

    if (timeout) {
        service->cancelTimeout(timeout);
        timeout = 0;
    }

    if (tricklingTriggers)
        tricklingTriggers = ttNone;
}

void Adapter::Xaction::allowAccess()
{
    prepFinalAction(actAllow);

    switch (sendingAb) {
    case opUndecided:
        if (!vbOffset()) // we have not nibbled at the host-buffered virgin message
            useVirgin();
        else
            useStored();
        break;
    case opRequested:
        // just wait for abMake() or abDiscard()
        break;
    case opOn: {
        const bool doneReceiving = receivingVb == opComplete || receivingVb == opNever;
        hostx().noteAbContentAvailable();
        if (doneReceiving) {
            sendingAb = opComplete;
            hostx().noteAbContentDone(vbComplete);
        }
        // else wait for more vb to send to the host
        break;
    }
    case opComplete: {
        // this might only happen if we get a scan answer after abDiscard()
        const bool doneReceiving = receivingVb == opComplete || receivingVb == opNever;
        Must(doneReceiving);
        // There is nothing new we can tell the host,
        // which should have stop()ed and destroyed us by now!
        break;
    }
    case opNever:
        throw TextExceptionHere("allowAccess() after useVirgin()");
        break;
    }
}

void Adapter::Xaction::blockAccess()
{
    prepFinalAction(actBlock);

    stopVb(false);

    switch (sendingAb) {
    case opUndecided:
        lastHostCall().blockVirgin();
        break;
    case opRequested:
        lastHostCall().adaptationAborted();
        break;
    case opOn:
        sendingAb = opComplete; // TODO: rename to opDone?
        lastHostCall().noteAbContentDone(false); // false even if vbComplete is true
        break;
    case opComplete:
        // this might happen if we get an answer after host calls abDiscard()
        lastHostCall().adaptationAborted();
        break;
    case opNever:
        throw TextExceptionHere("blockAccess() after useVirgin()");
        break;
    }

    // the host should call stop() and then destroy us
}

// The atEnd parameter sets vbComplete (when appropriate). noteVbContentDone()
// notification comes after we receive the last vb chunk, so we may receive the
// entire vb without knowing that we did. If the caller is not sure, it should
// call with false atEnd. This strategy ensures that atEnd is never true unless
// we are absolutely sure that we got the entire vb (i.e., no false positives).
// All false negative cases deal with errors where it is OK to tell the host
// that _ab_ is incomplete even if the host actually got everything.
void Adapter::Xaction::stopVb(const bool atEnd)
{
    if (receivingVb == opRequested || receivingVb == opOn) {
        hostx().vbStopMaking();
        receivingVb = opComplete;
        vbComplete = atEnd;
    } else
    if (receivingVb == opUndecided)
        receivingVb = opNever;
}

void Adapter::Xaction::debugAction(const std::string &act, const char *reason)
{
    // TODO: add and log transaction ID
    Debugger(flXaction) <<
        "eClamAv: " << act <<
        (reason ? ": " : "") << (reason ? reason : "") <<
        " (" << service->mode << ' ' << uri << ")";
}

void Adapter::Xaction::handleHuge(const char *where)
{
    debugAction(actSkipped, where);
    allowAccess(); // TODO: make allow/block decision configurable
}

void Adapter::Xaction::onAnswer(const Answer &answer)
{
    DebugFun(flXaction) << answer.statusCode;

    // Since we got an answer, cancel the pending timeout if any. We may still
    // have a timeout here because blocking scans bypass tellHostToResume().
    if (timeout) {
        service->cancelTimeout(timeout);
        timeout = 0;
    }

    switch (answer.statusCode) {
    case Answer::scClean:
        onClean();
        break;

    case Answer::scVirus:
        onVirus(answer.virusName);
        break;

    case Answer::scError:
        handleError(TextExceptionHere(answer.errorMsg));
        break;

    case Answer::scUnknown:
        throw TextExceptionHere("unknown scan result");
        break;
    }
}

void Adapter::Xaction::onClean()
{
    debugAction(actClean);
    allowAccess();
}

void Adapter::Xaction::onVirus(const std::string &virusName)
{
    debugAction(actVirus, virusName.c_str());
    virusId = virusName; // copy
    blockAccess();
}

void Adapter::Xaction::tellHostToResume(Answer *anAnswer)
{
    if (timeout) {
        // If we got an [async] answer, then cancel the pending timeout ASAP.
        // If we received a timeout notification, the old timeout was processed.
        if (anAnswer)
            service->cancelTimeout(timeout);
        timeout = 0;
    }

    DebugFun(flOperation) << hostx_ << " will resume " << this <<
        " for " << (anAnswer ? anAnswer->fileName : std::string("timeout"));

    // if we are stopped during async analysis, stop() tries to cancel the
    // thread, but it is possible that the cancellation comes after the
    // transaction has been added to WaitingXactions.
    if (hostx_) {
        Must(!answerToResumeWith);
        answerToResumeWith = anAnswer;
        hostx().resume();
    } else
        delete anAnswer;
}

void Adapter::Xaction::handleError(const std::exception &ex)
{
    // we can handle errors before/during scanning, but after we call use*(),
    // all errors must be propagated to the host via exceptions
    if (sendingAb != opUndecided) { // too late to change anything
        debugAction(actErrorLate, ex.what());
        throw ex;
    }

    if (service->blockOnError) {
        debugAction(actErrorBlock, ex.what());
        blockAccess();
    } else {
        debugAction(actErrorAllow, ex.what());
        allowAccess();
    }
}

const Adapter::TricklingConfig &Adapter::Xaction::tricklingConfig() const
{
    return service->tricklingConfig();
}

void Adapter::Xaction::tricklingCheckpoint(const TricklingTrigger trigger)
{
    DebugFun(flXaction) << std::hex << tricklingTriggers << '&' << trigger << std::dec;
    if ((tricklingTriggers & trigger) != 0) // interested in this event
        trickle();
}

void Adapter::Xaction::trickle()
{
    Time nextDropDelay;

    if (sendingAb == opUndecided) {
        size_t thisHeaderSize = 0;
        tricklingTriggers = startTrickling(thisHeaderSize, nextDropDelay);
        if (tricklingTriggers && thisHeaderSize > 0)
            trickleHeaderNow();
        // else trickling is disabled or we wait for something
    } else {
        size_t thisDropSize = 0;
        tricklingTriggers = keepTrickling(thisDropSize, nextDropDelay);
        if (tricklingTriggers && thisDropSize > 0)
            trickleBodyNow(thisDropSize);
        // else trickling is disabled or we wait for something
    }

    // whether we need a new timeout or not, we have to get rid of the old one
    // TODO: optimize timeout _changes_
    if (timeout) {
        service->cancelTimeout(timeout);
        timeout = 0;
    }

    if ((tricklingTriggers & ttTimeout) != 0) // we need a new timeout
        timeout = service->wakeMeUpToTrickle(self, nextDropDelay);
}

void Adapter::Xaction::trickleHeaderNow()
{
    useStored();
    trickledStamp = Time::Now(); // TODO: move to useAdapted() and abContent()
}

void Adapter::Xaction::trickleBodyNow(const size_t dropSize)
{
    Must(vbOffset() >= trickledSize);
    const Size allowable = vbOffset() - trickledSize;
    const Size gain = std::min(static_cast<Size>(dropSize), allowable);

    DebugFun(flOperation) << "allowing " << gain << " <= " << dropSize;

    if (gain) {
        trickledSize += gain;
        trickledStamp = Time::Now();
        hostx().noteAbContentAvailable();
    }
}

void Adapter::Xaction::reconfigure()
{
    DebugFun(flXaction) << this << " old triggers: 0x" << std::hex << tricklingTriggers << std::dec;

    // TODO: Better support for hot reconfiguration of accumulation limits. We
    // currently only notice new vbAccumulationMax in noteVbContentAvailable().

    if (tricklingTriggers == ttNone) // never overwrite ttNone
        return;

    /* pause trickling and then, if needed, restart it */

    if (timeout) {
        service->cancelTimeout(timeout);
        timeout = 0;
    }
    tricklingTriggers = ttReconfiguration;

    if (service->trickling())
        trickle();
}

void Adapter::Xaction::getUri()
{
    typedef const libecap::RequestLine *CLRLP;
    if (CLRLP virginLine = dynamic_cast<CLRLP>(&hostx().virgin().firstLine()))
        uri = virginLine->uri();
    else
    if (CLRLP causeLine = dynamic_cast<CLRLP>(&hostx().cause().firstLine()))
        uri = causeLine->uri();
}


void Adapter::Xaction::open()
{
    Must(!vbFile);
    vbFile = new FileBuffer(service->tmpFileNameTemplate);
}


void Adapter::Xaction::close()
{
    delete vbFile;
    vbFile = 0;
}

Adapter::Xaction::TricklingTriggers
Adapter::Xaction::startTrickling(size_t &headerSize, Time &nextDropDelay) const
{
    // first drop should be delayed for the configurable timeout
    if (tooEarlyToTrickle(headerSize, nextDropDelay, tricklingConfig().startDelay))
        return ttTimeout | ttReconfiguration;

    headerSize = 1; // any positive size; we are always sending the whole header
    nextDropDelay = tricklingConfig().period;
    return ttTimeout | ttReconfiguration;
}

Adapter::Xaction::TricklingTriggers
Adapter::Xaction::keepTrickling(size_t &thisDropSize, Time &nextDropDelay) const
{
    /* obey various trickling size limits */

    // Where do we want to be if there are no configurable limits?
    Size nextTrickledSize = SafeAdd(trickledSize, tricklingConfig().dropSize); // may be adjusted

    // do not trickle more than tricklingSizeMax bytes
    const Size tricklingSizeLimit = SafeAdd(tricklingConfig().sizeMax, 1);
    if (overLimit(nextTrickledSize, tricklingSizeLimit, "trickling_size_max"))
        return ttReconfiguration;

    // if we know where the body ends, do not trickle the last byte
    if (bodySize.known() && overLimit(nextTrickledSize, bodySize.value(), "known body size"))
        return ttNone;

    // if we do not know where the body ends, do not trickle the last known byte
    if (!bodySize.known() && overLimit(nextTrickledSize, vbOffset(), "possible body size")) {
        thisDropSize = 0; // no trickling for now
        nextDropDelay = tricklingConfig().period;
        // wait and re-check whether more virgin body bytes are available
        return ttVbContent | ttReconfiguration;
    }

    if (tooEarlyToTrickle(thisDropSize, nextDropDelay, tricklingConfig().period))
        return ttTimeout | ttReconfiguration;

    // if we were not over any limit, then we must be making progress,
    Must(tricklingConfig().dropSize); // provided the drop size is positive
    Must(nextTrickledSize > trickledSize);
    const Size thisDropSizeMax = nextTrickledSize - trickledSize;


    /* account for what is already available to the host */

    // the host could not have taken more than we made available
    Must(trickledSize >= abOffset);
    const Size stillAvailableForHost = trickledSize - abOffset;
    thisDropSize = (thisDropSizeMax > stillAvailableForHost) ?
        (thisDropSizeMax - stillAvailableForHost) :
        0; // no need to trickle any additional bytes yet
    // allow time drift; we are not a bandwidth shaper
    nextDropDelay = tricklingConfig().period;
    return ttTimeout | ttReconfiguration;
}

bool Adapter::Xaction::tooEarlyToTrickle(size_t &thisDropSize, Time &nextDropDelay, const Time minWaitTime) const
{
    const Time now = Time::Now();
    const Time elapsed = now - trickledStamp;
    if (minWaitTime <= elapsed)
        return false; // no, not too early; may trickle now

    // this may happen because of reconfiguration or ttVbContent wait, at least
    thisDropSize = 0;
    nextDropDelay = minWaitTime - elapsed;
    return true; // should result in ttTimeout wait
}

// if we have already trickled at or over the limit, returns true
// otherwise, adjusts desiredSize to obey the limit (if needed), returning false
bool Adapter::Xaction::overLimit(Size &desiredSize, const Size limit, const char *description) const
{
    if (trickledSize >= limit) {
        DebugFun(flOperation) << "already trickled at least " << description <<
            ": " << trickledSize << " >= " << limit;
        return true; // already trickled everything allowed (and possibly more)
    }

    if (desiredSize >= limit) {
        DebugFun(flOperation) << "do not trickle as much as " << description <<
            ": " << desiredSize << " >= " << limit;
        Must(limit > 0); // or the trickledSize test above would have succeeded
        desiredSize = limit-1; // we do not want to reach the limit (i.e., max+1)
    }

    return desiredSize <= trickledSize; // no progress, probably due to limit
}

const char *Adapter::Xaction::syncBodySize()
{
    Must(!bodySize.known());
    const libecap::Header &header = hostx().virgin().header();

    if (header.hasAny(libecap::headerTransferEncoding))
        return "chunked body";

    if (!header.hasAny(libecap::headerContentLength))
        return "EOF-terminated body";

    const libecap::Area lenVal = header.value(libecap::headerContentLength);
    const std::string buf(lenVal.start, lenVal.size);
    std::istringstream is(buf);
    libecap::BodySize::size_type contentLength = 0;
    if (!(is >> contentLength)) // TODO: Also check for garbage after the value.
        return "malformed Content-Length value";

    DebugFun(flXaction) << "expected body length: " << contentLength;
    bodySize = libecap::BodySize(contentLength);
    return "known body size";
}

