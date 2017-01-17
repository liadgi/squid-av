/* eCAP ClamAV Adapter                                http://www.e-cap.org/
 * Copyright (C) 2011 The Measurement Factory.
 * Distributed under GPL v2 without any warranty.                        */

#ifndef ECAP_CLAMAV_ADAPTER_XACTION_H
#define ECAP_CLAMAV_ADAPTER_XACTION_H

#include "Antivirus.h"
#include "Answer.h"
#include "Pointers.h"
#include "Time.h"

#include <libecap/adapter/xaction.h>
#include <libecap/host/host.h>
#include <libecap/host/xaction.h>
#include <libecap/common/memory.h>
#include <libecap/common/message.h>
#include <libecap/common/header.h>
#include <libecap/common/names.h>
#include <libecap/common/body_size.h>

#include <list>


namespace Adapter {

using libecap::size_type;

// Antivirus Answer that can be async-delivered to Xaction via Queue
class MyAnswer: public Answer
{
public:
    MyAnswer(const std::string & vbFileName, const XactionPointer &anX, Answers *answers);
    virtual ~MyAnswer();

    /* Answer API */
    virtual void deliver();

    XactionPointer xaction;

private:
    Answers *answers; // delivery queue
};

// eCAP adapter transaction that scans the virgin message using Antivirus API
// while optionally trickling virgin body bytes to the host application.
class Xaction: public libecap::adapter::Xaction, public Antivirus::User
{
public:
    Xaction(libecap::shared_ptr<Service> aService, libecap::host::Xaction *aHostX);
    virtual ~Xaction();

    // meta-information for the host transaction
    virtual const libecap::Area option(const libecap::Name &name) const;
    virtual void visitEachOption(libecap::NamedValueVisitor &visitor) const;

    // lifecycle
    virtual void start();
    virtual void stop();
    virtual void resume(); // check for decision

    // adapted body transmission control
    virtual void abDiscard();
    virtual void abMake();
    virtual void abMakeMore();
    virtual void abStopMaking();

    // adapted body content extraction and consumption
    virtual libecap::Area abContent(size_type offset, size_type size);
    virtual void abContentShift(size_type size);

    // virgin body state notification
    virtual void noteVbContentDone(bool atEnd);
    virtual void noteVbContentAvailable();

    // Antivirus::User API
    virtual void onAnswer(const Answer &answer);

    // give host control after async analysis
    void tellHostToResume(Answer *aAnswer);

    // whether we expect to do more work
    // in other words, whether neither stop() nor lastHostCall() happened
    bool active() const { return hostx_; }

    // suspends, resumes, or adjusts tricking as needed
    void reconfigure();

    // optimizes Service disconnect() speed
    typedef std::list<XactionPointer> Xactions;
    Xactions::iterator *serviceRegistration;

    XactionPointer self;

protected:
    bool shouldExamine(); // decide whether to receive and scan the message

    void handleHuge(const char *where); // deal with over-the-limit vb size
    void handleError(const std::exception &ex);

    libecap::host::Xaction &hostx(); // returns host transaction or throws
    libecap::host::Xaction &lastHostCall(); // hostx() that clears hostx_

    void adaptContent(std::string &chunk); // converts vb to ab
    void stopVb(const bool atEnd); // stops receiving vb (if we are receiving it)
    void useVirgin(); // tell host to use virgin message
    void useStored(); // tell host to use stored message
    void allowAccess(); // tell host to forward the message
    void blockAccess(); // tell host to deny user access
    void getUri();

    void onClean();
    void onVirus(const std::string &virusName);


    /* tricking */

    // convenience wrapper; throws if trickling is disabled
    const TricklingConfig &tricklingConfig() const;

    typedef enum {
        ttNone = 0, // no more drops ever, even after a reconfiguration
        ttTimeout = 0x01, // more drops are possible after a timeout
        ttVbContent = 0x02, // more drops are possible after noteVbContent*()
        ttReconfiguration = 0x10, // more drops are possible after reconfiguration
        ttAny = 0xFF // a testing mask to indicate that more drops are possible
    } TricklingTrigger; // what event may create additional trickling drops
    typedef unsigned int TricklingTriggers; // zero or more TricklingTrigger(s)

    // avails headers or body bytes for the host as/if needed
    void tricklingCheckpoint(const TricklingTrigger trigger);

    // calculates whether to trickle the headers now and the first body drop delay
    // returns which event(s) should trigger the next drop, if any
    virtual TricklingTriggers startTrickling(size_t &thisDropSize, Time &nextDropDelay) const;

    // calculates this drop size and next drop delay
    // returns which event(s) should trigger the next drop, if any
    virtual TricklingTriggers keepTrickling(size_t &thisDropSize, Time &nextDropDelay) const;

    // if we have not waited long enough, then sets nextDropDelay, clears
    // thisDropSize, and returns true; otherwise, just returns false
    bool tooEarlyToTrickle(size_t &thisDropSize, Time &nextDropDelay, const Time minWaitTime) const;

    // makes cloned virgin message header available to host
    void trickleHeaderNow();
    // makes the next dropSize in the file buffer available to host if possible
    void trickleBodyNow(const size_t dropSize);

    void debugAction(const std::string &action, const char *detail = 0);

    void open(); // creates staging file
    void close(); // removes staging file

private:
    typedef enum { actPending, actAllow, actBlock } FinalAction;

    // code shared by allowAccess() and blockAccess()
    void prepFinalAction(const FinalAction action);

    void trickle(); // trickling step, protected by tricklingCheckpoint()
    const char *syncBodySize();
    bool overLimit(Size &desiredSize, const Size limit, const char *description) const;

    Size vbOffset() const; // virgin body bytes received so far

    void disconnect(); // expect no more notifications from Service or Host

    libecap::shared_ptr<const Service> service; // configuration access
    libecap::host::Xaction *hostx_; // host transaction representative
    libecap::Area uri; // Request-URI from headers, for logging

    Timeout *timeout; // opaque Service registration for deadline notification
    Answer *answerToResumeWith; // valid in the tellHostToResume()..resume() gap
    std::string virusId; // Antivirus-reported "virus name" or empty

    libecap::BodySize bodySize; // may be unknown

    FileBuffer *vbFile; // a temporary file for the virgin body being received
    Size abOffset; // adapted body bytes "consumed" by host
    Size trickledSize; // the number of bytes the host may trickle
    Time trickledStamp; // the last trickling time

    typedef enum { opUndecided, opRequested, opOn, opComplete, opNever } OperationState;
    OperationState receivingVb; // receiving of virgin body state
    OperationState sendingAb; // sending of adapted body state

    // event(s) that may trigger more trickling
    TricklingTriggers tricklingTriggers;

    FinalAction finalAction; // either actPending or what we have decided to do
    bool vbComplete; // got entire virgin body
};

} // namespace Adapter

#endif
