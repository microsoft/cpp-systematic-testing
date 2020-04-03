// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef SYSTEMATIC_TESTING_RESOURCES_H
#define SYSTEMATIC_TESTING_RESOURCES_H

#include <optional>

#include "systematic_testing.h"

namespace SystematicTesting::Resources
{
    // Returns a new resource id, or nullopt if such an id cannot be assigned.
    std::optional<size_t> assign_resource_id()
    {
        std::optional<size_t> id = std::nullopt;
        if (auto test_engine = GetTestEngine())
        {
            id = test_engine->create_next_resource();
        }

        return id;
    }

    // Manages a controlled resource that can be used to instrument synchronization primitives
    // that can be acquired by controlled operations in a shared or exclusive manner.
    class SynchronizedResource final
    {
    public:
        // The status of the resource.
        enum class Status
        {
            Released = 0,
            AcquiredExclusive,
            AcquiredShared
        };

        SynchronizedResource(bool is_reentrant = false) noexcept :
            m_id(assign_resource_id()),
            m_is_reentrant(is_reentrant),
            m_status(Status::Released)
        {
        }

        ~SynchronizedResource()
        {
            auto test_engine = GetTestEngine();
            if (test_engine && m_id.has_value())
            {
                test_engine->delete_resource(m_id.value());
            }
        }

        // Acquires the resource in an exclusive or shared manner.
        void acquire(bool is_shared = false)
        {
            auto test_engine = GetTestEngine();
            if (test_engine && test_engine->is_resource_attached(m_id))
            {
                // Loop until the resource can be acquired.
                while (true)
                {
                    // The resource can only be acquired in the following cases:
                    // 1. The resource is released.
                    // 2. The resource is shared and is being acquired in a shared manner.
                    // 3. The resource is reentrant, exclusive and is being acquired by the same owner.
                    if (m_status == Status::Released ||
                        (is_shared && m_status == Status::AcquiredShared) ||
                        (m_is_reentrant && m_status == Status::AcquiredExclusive &&
                        test_engine->is_resource_owned_by_current_operation(m_id.value())))
                    {
                        // Acquire the resource and stop retrying.
                        m_status = is_shared ? Status::AcquiredShared : Status::AcquiredExclusive;
                        break;
                    }

                    // Notify the engine that the current operation is blocked
                    // until the resource is released.
                    test_engine->wait_resource(m_id.value());
                }

                if (test_engine->settings().is_resource_race_checking_enabled())
                {
                    // Introduce an interleaving before the resource is acquired.
                    test_engine->schedule_next_operation();
                }

                // Notify the engine that the current operation has acquired the resource.
                test_engine->acquire_resource(m_id.value());
            }
        }

        // Releases the resource if it was acquired exclusively or in a shared manner.
        void release()
        {
            auto test_engine = GetTestEngine();
            if (test_engine && test_engine->is_resource_attached(m_id))
            {
                if (m_status != Status::Released)
                {
                    // Notify the engine that the resource has been released by this owner.
                    if (test_engine->try_release_resource(m_id.value()))
                    {
                        m_status = Status::Released;
                        if (test_engine->settings().is_resource_race_checking_enabled())
                        {
                            // Introduce an interleaving after the resource is released.
                            test_engine->schedule_next_operation();
                        }
                    }
                }
            }
        }

        // Returns the current status of the resource.
        Status status() const noexcept
        {
            return m_status;
        }

    private:
        // The unique id of this resource.
        const std::optional<size_t> m_id;

        // True if the resource can be acquired multiple times by the same owner.
        const bool m_is_reentrant;

        // The status of this resource.
        Status m_status;
    };
} // namespace SystematicTesting::Resources

#endif // SYSTEMATIC_TESTING_RESOURCES_H
