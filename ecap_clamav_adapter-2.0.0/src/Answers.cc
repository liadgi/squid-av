/* eCAP ClamAV Adapter                                http://www.e-cap.org/
 * Copyright (C) 2011 The Measurement Factory.
 * Distributed under GPL v2 without any warranty.                        */

#include "Adapter.h"
#include "Antivirus.h"
#include "Answer.h"
#include "Answers.h"


Adapter::Answers::Answers():
    references(1)
{
    pthread_mutex_init(&lock, 0); // needs pthread_mutex_destroy()
}

Adapter::Answers::~Answers()
{
    while (!queue.empty()) {
        delete queue.front();
        queue.pop_front();
    }
    pthread_mutex_destroy(&lock);
}

void Adapter::Answers::use()
{
    pthread_mutex_lock(&lock);
    ++references;
    pthread_mutex_unlock(&lock);
}

int Adapter::Answers::abandon()
{
    int counter = 0;

    {
        pthread_mutex_lock(&lock);
        counter = --references;
        pthread_mutex_unlock(&lock);
    }

    if (!counter)
        delete this;

    return counter;
}

int Adapter::Answers::users() const
{
    int counter = 0;

    {
        pthread_mutex_lock(&lock);
        counter = references;
        pthread_mutex_unlock(&lock);
    }

    return counter;
}

void Adapter::Answers::put(Answer *answer)
{
    pthread_mutex_lock(&lock);
    queue.push_back(answer);
    pthread_mutex_unlock(&lock);
}

bool Adapter::Answers::empty() const
{
    bool isEmpty = true;

    {
        pthread_mutex_lock(&lock);
        isEmpty = queue.empty();
        pthread_mutex_unlock(&lock);
    }

    return isEmpty;
}

Adapter::Answer *Adapter::Answers::get()
{
    Answer *answer = 0;

    {
        pthread_mutex_lock(&lock);
        if (!queue.empty()) {
            answer = queue.front();
            queue.pop_front();
        }
        pthread_mutex_unlock(&lock);
    }

    return answer;
}
