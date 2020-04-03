// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "systematic_testing.h"

static SystematicTesting::TestEngine* g_pEngine = nullptr;

void SystematicTesting::InitTestEngine(SystematicTesting::Settings settings)
{
    if (g_pEngine)
    {
        // We only allow one global engine to be set at the same time per process.
        throw SystematicTesting::Exceptions::TestEngineAlreadyInitializedError();
    }

    g_pEngine = new TestEngine(settings);
}

void SystematicTesting::RemoveTestEngine()
{
    delete g_pEngine;
    g_pEngine = nullptr;
}

SystematicTesting::TestEngine* SystematicTesting::GetTestEngine()
{
    return g_pEngine;
}

thread_local std::optional<size_t> tls_executing_op_id = std::nullopt;

void SystematicTesting::Runtime::set_thread_local_operation_state(size_t op_id)
{
    tls_executing_op_id = op_id;
}

void SystematicTesting::Runtime::remove_thread_local_operation_state(size_t op_id)
{
    if (tls_executing_op_id.has_value() && tls_executing_op_id.value() == op_id)
    {
        tls_executing_op_id = std::nullopt;
    }
}

std::optional<size_t> SystematicTesting::Runtime::get_thread_local_executing_operation_id()
{
    return tls_executing_op_id;
}
