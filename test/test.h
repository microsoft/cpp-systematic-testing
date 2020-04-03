// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef SYSTEMATIC_TESTING_TEST_H
#define SYSTEMATIC_TESTING_TEST_H

#include <chrono>
#include <iostream>
#include "systematic_testing.h"

using namespace SystematicTesting;

void assert(bool predicate, std::string error)
{
    if (!predicate)
    {
        throw error;
    }
}

size_t total_time(std::chrono::steady_clock::time_point start_time)
{
    auto end_time = std::chrono::steady_clock::now();
    return (size_t)std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
}

Settings CreateDefaultSettings()
{
    auto settings = Settings();
    settings.with_verbosity_level(VerbosityLevel::Exhaustive);
    settings.with_random_generator_seed(0);
    settings.with_random_strategy();
    settings.with_partially_controlled_concurrency_allowed(false);
    return settings;
}

class SystematicTestIterationContext
{
public:
    const uint32_t id;

    SystematicTestIterationContext(uint32_t iteration, bool start_controlled) :
        id(iteration)
    {
        std::cout << "[test] iteration " << id << std::endl;
        GetTestEngine()->prepare();

        if (start_controlled)
        {
            TakeControl();
        }
    }

    virtual ~SystematicTestIterationContext()
    {
        GetTestEngine()->detach();
    }

    void TakeControl()
    {
        assert(!m_is_attached, "The test engine is already attached.");
        m_is_attached = true;
        GetTestEngine()->attach();
    }

private:
    bool m_is_attached = false;
};

class SystematicTestEngineContext
{
public:
    SystematicTestEngineContext(Settings settings, uint32_t iterations) :
        m_iterations(0),
        m_total_iterations(iterations)
    {
        // Set the global test engine.
        InitTestEngine(settings);
    }

    std::unique_ptr<SystematicTestIterationContext> next_iteration(bool start_controlled = true)
    {
        return m_iterations < m_total_iterations ?
            std::make_unique<SystematicTestIterationContext>(m_iterations++, start_controlled) :
            std::unique_ptr<SystematicTestIterationContext>();
    }

    std::unique_ptr<SystematicTestIterationContext> next_iteration_if(bool condition, bool start_controlled = true)
    {
        return m_iterations < m_total_iterations && condition ?
            std::make_unique<SystematicTestIterationContext>(m_iterations++, start_controlled) :
            std::unique_ptr<SystematicTestIterationContext>();
    }

    TestReport report()
    {
        return GetTestEngine()->report();
    }

    uint32_t total_iterations() const
    {
        return m_total_iterations;
    }

    ~SystematicTestEngineContext()
    {
        // Remove the global test engine.
        RemoveTestEngine();
    }

private:
    uint32_t m_iterations;
    const uint32_t m_total_iterations;
};

#endif // SYSTEMATIC_TESTING_TEST_H
