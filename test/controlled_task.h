// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef SYSTEMATIC_TESTING_CONTROLLED_TASK_H
#define SYSTEMATIC_TESTING_CONTROLLED_TASK_H

#include <any>
#include <future>
#include <optional>
#include <iostream>
#include <thread>

#include "systematic_testing.h"

using namespace std::chrono_literals;
using namespace SystematicTesting;

template<typename ResultType>
class ControlledTaskBase
{
public:
    explicit ControlledTaskBase(std::function<ResultType()> func) :
        m_test_engine(GetTestEngine()),
        m_thread(),
        m_func(func),
        m_result(std::nullopt)
    {
        
    }

    virtual ~ControlledTaskBase()
    {
        if (m_thread->joinable())
        {
            m_thread->join();
        }
    }

    void start()
    {
        size_t op_id = m_test_engine->create_next_operation().value();
        m_thread = std::make_unique<std::thread>([this, op_id]()
        {
            m_test_engine->start_operation(op_id);
            execute(m_func, op_id);
            m_test_engine->complete_current_operation();
        });

        m_test_engine->schedule_next_operation();
    }

    void wait()
    {
        m_test_engine->pause_operation_until_condition([this]() {
            return m_result.has_value();
        });
    }

protected:
    std::optional<std::any> m_result;

    virtual void execute(std::function<ResultType()>& func, size_t op_id) = 0;

private:
    TestEngine* m_test_engine;
    std::unique_ptr<std::thread> m_thread;
    std::function<ResultType()> m_func;
};

template<typename ResultType>
class ControlledTask final : public ControlledTaskBase<ResultType>
{
    using BaseType = ControlledTaskBase<ResultType>;

public:
    explicit ControlledTask(std::function<void()> func)
        : BaseType(func)
    {
    }

    ResultType get()
    {
        BaseType::wait();
        return BaseType::m_result.value();
    }

protected:
    void execute(std::function<ResultType()>& func, size_t op_id) override
    {
        ResultType result = func();
        BaseType::m_result = result;
    }
};

template<>
class ControlledTask<void> final : public ControlledTaskBase<void>
{
    using BaseType = ControlledTaskBase<void>;

public:
    explicit ControlledTask(std::function<void()> func)
        : BaseType(func)
    {
    }

protected:
    void execute(std::function<void()>& func, size_t op_id) override
    {
        func();
        m_result = true;
    }
};

#endif // SYSTEMATIC_TESTING_CONTROLLED_TASK_H
