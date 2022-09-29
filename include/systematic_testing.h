// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef SYSTEMATIC_TESTING_H
#define SYSTEMATIC_TESTING_H

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <functional>
#include <iostream>
#include <iterator>
#include <list>
#include <map>
#include <numeric>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

#ifdef __linux__
#   ifdef SYSTEST_EXPORT
#      define SYSTEST_API __attribute__((visibility("default")))
#   else
#      define SYSTEST_API 
#   endif
#elif _WIN32
#   ifdef SYSTEST_EXPORT
#      define SYSTEST_API __declspec(dllexport)
#   else
#      define SYSTEST_API __declspec(dllimport)
#   endif
#else 
#   ifdef SYSTEST_EXPORT
#      define SYSTEST_API 
#   else
#      define SYSTEST_API 
#   endif
#endif

namespace SystematicTesting
{
    class TestEngine;

    // Used to convert microseconds to ticks.
    static const size_t TICKS_PER_MICROSECOND = 10;

    // The verbosity level used by the scheduler.
    enum class VerbosityLevel
    {
        None = 0,
        Error,
        Warning,
        Info,
        Debug,
        Exhaustive
    };

    class Logger
    {
    public:
        Logger(VerbosityLevel verbosity_level) noexcept :
            m_verbosity_level(verbosity_level)
        {
        }

        template<class... Args>
        void log_error(const Args&... args) const
        {
            if (m_verbosity_level >= VerbosityLevel::Error)
            {
                (std::cout << ... << args) << std::endl;
            }
        }

        template<class... Args>
        void log_warning(const Args&... args) const
        {
            if (m_verbosity_level >= VerbosityLevel::Warning)
            {
                (std::cout << ... << args) << std::endl;
            }
        }

        template<class... Args>
        void log_info(const Args&... args) const
        {
            if (m_verbosity_level >= VerbosityLevel::Info)
            {
                (std::cout << ... << args) << std::endl;
            }
        }

        template<class... Args>
        void log_debug(const Args&... args) const
        {
            if (m_verbosity_level >= VerbosityLevel::Debug)
            {
                (std::cout << ... << args) << std::endl;
            }
        }

        template<class... Args>
        void log_exhaustive(const Args&... args) const
        {
            if (m_verbosity_level >= VerbosityLevel::Exhaustive)
            {
                (std::cout << ... << args) << std::endl;
            }
        }

        template<class... Args>
        static std::string format(const Args&... args)
        {
            std::ostringstream result;
            (result << ... << args);
            return result.str();
        }

        // Returns the defined verbosity level.
        VerbosityLevel verbosity_level() const noexcept
        {
            return m_verbosity_level;
        }

    private:
        // The defined verbosity level.
        const VerbosityLevel m_verbosity_level;
    };

    // The type of the exploration strategy to use.
    enum class StrategyType
    {
        Random = 0,
        Prioritization,
        Replay
    };

    // The systematic test engine settings.
    class Settings
    {
    public:
        Settings() noexcept :
            m_strategy_type(StrategyType::Random),
            m_strategy_bound(100),
            m_seed_state(0),
            m_replay_trace(),
            m_is_resource_race_checking_enabled(false),
            m_is_partially_controlled_concurrency_allowed(true),
            m_partially_controlled_concurrency_resolution_interval(100),
            m_verbosity_level(VerbosityLevel::None)
        {
        }

        // Configures the engine to use the random exploration strategy with the specified
        // probability of deviating from the currently scheduled enabled operation.
        void with_random_strategy(size_t probability = 100)
        {
            size_t max_probability = 100;
            if (probability > max_probability)
            {
                throw std::runtime_error(Logger::format("cannot assign probability greater than ", max_probability));
            }

            m_strategy_type = StrategyType::Random;
            m_strategy_bound = probability;
        }

        // Configures the engine to use the prioritized exploration strategy with the specified
        // bound of priority change points that allow deviation from the currently scheduled
        // enabled operation.
        void with_prioritization_strategy(size_t priority_change_bound = 10)
        {
            m_strategy_type = StrategyType::Prioritization;
            m_strategy_bound = priority_change_bound;
        }

        // Configures the engine to use the replay exploration strategy with the specified random generator
        // seed and trace (sequence of nondeterministic choices) to reproduce an execution.
        void with_replay_strategy(const std::string& trace)
        {
            m_strategy_type = StrategyType::Replay;
            m_replay_trace = trace;
        }

        // Configures the engine to enable race checking for synchronization resources, which introduces
        // extra scheduling points when an operation accesses a resource.
        void with_resource_race_checking_enabled(bool is_enabled) noexcept
        {
            m_is_resource_race_checking_enabled = is_enabled;
        }

        // Configures the engine to allow executions with uncontrolled concurrency and
        // enables heuristics to try resolve such instances while maintaining as high
        // coverage as possible.
        void with_partially_controlled_concurrency_allowed(bool is_allowed = true) noexcept
        {
            m_is_partially_controlled_concurrency_allowed = is_allowed;
        }

        // Configures the time interval (in microseconds) to wait before checking
        // if uncontrolled concurrency has resolved.
        void with_partially_controlled_concurrency_resolution_interval(size_t interval) noexcept
        {
            m_partially_controlled_concurrency_resolution_interval = interval;
        }

        // Configures the engine to use the specified initial random generator seed.
        // Each new test iteration increments this seed by 1 to assign a unique seed
        // per iteration.
        void with_random_generator_seed(size_t seed) noexcept
        {
            m_seed_state = seed;
        }

        // Configures the engine to use the defined verbosity level.
        void with_verbosity_level(VerbosityLevel verbosity_level) noexcept
        {
            m_verbosity_level = verbosity_level;
        }

        // Returns the type of the installed exploration strategy.
        StrategyType exploration_strategy() const noexcept
        {
            return m_strategy_type;
        }

        // Returns an exploration strategy specific bound.
        size_t exploration_strategy_bound() const noexcept
        {
            return m_strategy_bound;
        }

        // Checks if race checking for synchronization resources is enabled.
        bool is_resource_race_checking_enabled() const noexcept
        {
            return m_is_resource_race_checking_enabled;
        }

        // Checks if partially controlled concurrency is allowed.
        bool is_partially_controlled_concurrency_allowed() const noexcept
        {
            return m_is_partially_controlled_concurrency_allowed;
        }

        // Returns the time interval (in microseconds) to wait before checking
        // if uncontrolled concurrency has resolved.
        size_t partially_controlled_concurrency_resolution_interval() const noexcept
        {
            return m_partially_controlled_concurrency_resolution_interval;
        }

        // Returns the seed used by randomized strategies.
        size_t random_seed() const noexcept
        {
            return m_seed_state;
        }

        // Returns the trace used by the replay strategy to reproduce an execution.
        const std::string& replay_trace() const noexcept
        {
            return m_replay_trace;
        }

        // Returns the defined verbosity level.
        VerbosityLevel verbosity_level() const noexcept
        {
            return m_verbosity_level;
        }

    private:
        // The execution exploration strategy.
        StrategyType m_strategy_type;

        // A strategy-specific bound.
        size_t m_strategy_bound;

        // The seed used by randomized strategies.
        size_t m_seed_state;

        // The trace used by the replay strategy to reproduce an execution.
        std::string m_replay_trace;

        // True if race checking for resources is enabled.
        bool m_is_resource_race_checking_enabled;

        // True if partially controlled concurrency is allowed.
        bool m_is_partially_controlled_concurrency_allowed;

        // The time interval (in microseconds) to wait before checking
        // if uncontrolled concurrency has resolved.
        size_t m_partially_controlled_concurrency_resolution_interval;

        // The defined verbosity level.
        VerbosityLevel m_verbosity_level;
    };

    // Report with exploration statistics and coverage information.
    class TestReport
    {
    private:
        // Give private access to the test engine.
        friend class SystematicTesting::TestEngine;

    public:
        // Returns the number of iterations performed.
        size_t iterations() const noexcept
        {
            return m_iterations;
        }

        // Returns the number of bugs found during testing.
        size_t bugs_found() const noexcept
        {
            return m_bugs_found;
        }

        // Returns the number of unique execution paths explored during testing.
        size_t explored_execution_paths() const noexcept
        {
            return m_explored_paths.size();
        }

        // Returns the number of unique states visited during testing.
        size_t visited_states() const noexcept
        {
            return m_visited_states.size();
        }

        // Returns the total number of scheduling decisions.
        size_t total_scheduling_decisions() const noexcept
        {
            return m_scheduling_decisions;
        }

        // Returns the average number of scheduling decisions per iteration.
        size_t avg_scheduling_decisions() const noexcept
        {
            return m_iterations > 0 ? (size_t) std::round(m_scheduling_decisions / m_iterations) : 0;
        }

        // Returns the total number of controlled operations.
        size_t total_controlled_operations() const noexcept
        {
            return m_operations;
        }

        // Returns the average number of controlled operations per iteration.
        size_t avg_controlled_operations() const noexcept
        {
            return m_iterations > 0 ? (size_t) std::round(m_operations / m_iterations) : 0;
        }

        // Returns the number of unique controlled operation creation sequences.
        size_t controlled_operation_creation_sequences() const noexcept
        {
            return m_op_creation_sequences;
        }

        // Returns the max number of controlled operations that were enabled for scheduling
        // at the same time during testing.
        size_t max_concurrency_degree() const noexcept
        {
            return m_concurrency_degree;
        }

        // Returns the total number of controlled resources.
        size_t total_controlled_resources() const noexcept
        {
            return m_resources;
        }

        // Returns the average number of controlled resources per iteration.
        size_t avg_controlled_resources() const noexcept
        {
            return m_iterations > 0 ? (size_t) std::round(m_resources / m_iterations) : 0;
        }

        // Returns the max number of synchronization resources that were controlled
        // at the same time during testing.
        size_t max_synchronization_degree() const noexcept
        {
            return m_synchronization_degree;
        }

        // Returns the total number of uncontrolled threads.
        size_t total_uncontrolled_threads() const noexcept
        {
            return m_uncontrolled_threads;
        }

        // Returns the average number of uncontrolled threads per iteration.
        size_t avg_uncontrolled_threads() const noexcept
        {
            return m_iterations > 0 ? (size_t) std::round(m_uncontrolled_threads / m_iterations) : 0;
        }

        // Returns the total number of detached threads.
        size_t total_detached_threads() const noexcept
        {
            return m_detached_threads + m_global_detached_threads;
        }

        // Returns the seed used in the last test iteration.
        size_t last_seed() const noexcept
        {
            return m_last_seed;
        }

        // Returns the sequence of choices made in the last test iteration, which can be used
        // to replay the same test iteration if configured in the test engine settings.
        const std::string& last_trace() const noexcept
        {
            return m_last_trace;
        }

        // Returns the total test duration in milliseconds across all iterations.
        size_t elapsed_time() const noexcept
        {
            return m_elapsed_test_time;
        }

        // Returns the average test duration in milliseconds per iteration.
        size_t avg_elapsed_time() const noexcept
        {
            return m_iterations > 0 ? (size_t) std::round(m_elapsed_test_time / m_iterations) : 0;
        }

        // Returns the total unattached duration in milliseconds across all iterations.
        size_t elapsed_unattached_time() const noexcept
        {
            return m_elapsed_unattached_time;
        }

        // Returns the average unattached duration in milliseconds per iteration.
        size_t avg_elapsed_unattached_time() const noexcept
        {
            return m_iterations > 0 ? (size_t) std::round(m_elapsed_unattached_time / m_iterations) : 0;
        }

        // Returns a string containing exploration statistics and coverage metrics.
        std::string to_string() const
        {
            std::ostringstream report;
            report << "========================================================" << std::endl;
            report << "===== exploration information and coverage metrics =====" << std::endl;
            report << "========================================================" << std::endl;
            report << "|_ used the '" << m_strategy << "' exploration strategy." << std::endl;

            report << "|_ ran '" << m_iterations << "' test iteration" << (m_iterations == 1 ? "" : "s") << "." << std::endl;
            if (m_iterations > 0)
            {
                report << "|  |_ found '" << m_bugs_found << "' bug" << (m_bugs_found == 1 ? "" : "s") << "." << std::endl;
                report << "|  |_ explored '" << m_explored_paths.size() << "' unique path" <<
                    (m_explored_paths.size() == 1 ? "" : "s") << "." << std::endl;
                report << "|  |_ visited '" << m_visited_states.size() << "' unique state" <<
                    (m_visited_states.size() == 1 ? "" : "s") << "." << std::endl;
                report << "|  |_ last iteration used the '" << m_last_seed << "' seed." << std::endl;

                if (m_scheduling_decisions > 0)
                {
                    report << "|_ scheduling decisions:" << std::endl;
                    report << "|  |_ '" << m_scheduling_decisions << "' decisions ('" << avg_scheduling_decisions() <<
                        "' per iteration)." << std::endl;
                }

                if (m_operations > 0)
                {
                    report << "|_ controlled operations (i.e., tasks and threads):" << std::endl;
                    report << "|  |_ '" << m_operations << "' operations ('" << avg_controlled_operations() <<
                        "' per iteration)." << std::endl;
                    report << "|  |_ '" << m_op_creation_sequences << "' unique creation sequences." << std::endl;
                    report << "|  |_ '" << m_concurrency_degree << "' max degree of concurrency." << std::endl;
                }

                if (m_resources > 0)
                {
                    report << "|_ controlled resources (i.e., locks):" << std::endl;
                    report << "|  |_ '" << m_resources << "' resources ('" << avg_controlled_resources() <<
                        "' per iteration)." << std::endl;
                    report << "|  |_ '" << m_synchronization_degree << "' max degree of synchronization." << std::endl;
                }

                auto detached_threads = m_detached_threads + m_global_detached_threads;
                if (m_uncontrolled_threads > 0 || detached_threads > 0)
                {
                    report << "|_ uncontrolled concurrency:" << std::endl;
                    if (m_uncontrolled_threads > 0)
                    {
                        report << "|  |_ detected '" << m_uncontrolled_threads << "' uncontrolled threads ('" <<
                            avg_uncontrolled_threads() << "' per iteration)." << std::endl;
                    }

                    if (detached_threads > 0)
                    {
                        report << "|  |_ detected '" << detached_threads << "' detached threads." << std::endl;
                    }
                }

                report << "|_ elapsed time in milliseconds:" << std::endl;
                report << "|  |_ '" << m_elapsed_test_time << "ms' ('" << avg_elapsed_time() <<
                    "ms' per iteration)." << std::endl;
                report << "|  |_ '" << m_elapsed_unattached_time << "ms' while unattached ('" <<
                    avg_elapsed_unattached_time() << "ms' per iteration)." << std::endl;
            }

            report << "========================================================";
            return report.str();
        }

    private:
        // The exploration strategy used during testing.
        const std::string m_strategy;

        // Number of test iterations completed.
        size_t m_iterations;

        // Number of bugs found during testing.
        size_t m_bugs_found;

        // Set of unique execution paths that were explored during testing.
        std::set<std::string> m_explored_paths;

        // Set of unique states that were visited during testing.
        std::set<size_t> m_visited_states;

        // Number of scheduling decisions taken during testing.
        size_t m_scheduling_decisions;

        // The total number of operations that were controlled during testing.
        size_t m_operations;

        // Number of unique controlled operation creation sequences during testing.
        size_t m_op_creation_sequences;

        // The max number of controlled operations that were enabled for scheduling
        // at the same time during testing.
        size_t m_concurrency_degree;

        // The total number of resources that were controlled during testing.
        size_t m_resources;

        // The max number of synchronization resources that were controlled
        // at the same time during testing.
        size_t m_synchronization_degree;

        // The total number of known uncontrolled threads during testing.
        size_t m_uncontrolled_threads;

        // The total number of known detached threads during testing.
        size_t m_detached_threads;

        // The total number of known detached threads during testing.
        size_t m_global_detached_threads;

        // The seed used by the last test iteration.
        size_t m_last_seed;

        // The sequence of nondeterministic choices made in the last test iteration.
        std::string m_last_trace;

        // The test duration in milliseconds across all iterations.
        size_t m_elapsed_test_time;

        // The unattached duration in milliseconds across all iterations.
        size_t m_elapsed_unattached_time;

        TestReport(const std::string& strategy) noexcept :
            m_strategy(strategy),
            m_iterations(0),
            m_bugs_found(0),
            m_explored_paths(),
            m_visited_states(),
            m_scheduling_decisions(0),
            m_operations(0),
            m_op_creation_sequences(0),
            m_concurrency_degree(0),
            m_resources(0),
            m_synchronization_degree(0),
            m_uncontrolled_threads(0),
            m_detached_threads(0),
            m_global_detached_threads(0),
            m_last_seed(0),
            m_last_trace(),
            m_elapsed_test_time(0),
            m_elapsed_unattached_time(0)
        {
        }
    };

    namespace Exceptions
    {
        class TestEngineNotInitializedError : public std::runtime_error
        {
        public:
            TestEngineNotInitializedError() : std::runtime_error("test engine is not initialized") {}
        };

        class TestEngineAlreadyInitializedError : public std::runtime_error
        {
        public:
            TestEngineAlreadyInitializedError() : std::runtime_error("test engine is already initialized") {}
        };

        class TestEngineDetachedError : public std::runtime_error
        {
        public:
            TestEngineDetachedError() : std::runtime_error("test engine is detached") {}
        };

        class OperationAlreadyExistsError : public std::runtime_error
        {
        public:
            OperationAlreadyExistsError(size_t op_id)
                : std::runtime_error(Logger::format("operation '", op_id, "' already exists"))
            {}
        };

        class OperationNotFoundError : public std::runtime_error
        {
        public:
            OperationNotFoundError(size_t op_id)
                : std::runtime_error(Logger::format("operation '", op_id, "' does not exist"))
            {}
        };

        class ResourceAlreadyExistsError : public std::runtime_error
        {
        public:
            ResourceAlreadyExistsError(size_t resource_id)
                : std::runtime_error(Logger::format("resource '", resource_id, "' already exists"))
            {}
        };

        class ResourceNotFoundError : public std::runtime_error
        {
        public:
            ResourceNotFoundError(size_t resource_id)
                : std::runtime_error(Logger::format("resource '", resource_id, "' does not exist"))
            {}
        };

        class UncontrolledInvocationError : public std::runtime_error
        {
        public:
            UncontrolledInvocationError() : std::runtime_error("uncontrolled invocation") {}
        };

        class DeadlockError : public std::runtime_error
        {
        public:
            DeadlockError() : std::runtime_error("deadlock detected") {}
        };

        class InstrumentationError : public std::runtime_error
        {
        public:
            InstrumentationError(std::string error) : std::runtime_error(Logger::format("instrumentation error(", error, ")")) {}
        };
    } // namespace SystematicTesting::Exceptions

    namespace Runtime
    {
        // The status of a controlled operation.
        enum class OperationStatus
        {
            None = 0,
            Enabled,
            BlockedOnWaitAll,
            BlockedOnWaitAny,
            BlockedOnResource,
            Completed
        };

        // Models a concurrent operation that is controlled by the test engine.
        class Operation
        {
        private:
            // Give private access to the test engine.
            friend class SystematicTesting::TestEngine;

            // The creation sequence vector of this operation.
            std::vector<size_t> m_creation_seq;

        public:
            // The unique id of this operation.
            const size_t id;

            // The creation sequence id of this operation.
            const size_t seq_id;

            // The test iteration associated with this operation.
            const size_t iteration;

            Operation(size_t op_id, Operation* const parent_op, size_t iteration) noexcept :
                m_creation_seq(get_next_creation_seq(op_id, parent_op)),
                id(op_id),
                seq_id(get_seq_hash()),
                iteration(iteration),
                m_status(OperationStatus::None),
                m_cv(),
                m_is_scheduled(false),
                m_dependencies(),
                m_dependent_resource_id(std::nullopt),
                m_child_op_count(0)
            {
            }

            Operation(Operation&& op) = delete;
            Operation(Operation const&) = delete;

            Operation& operator=(Operation&& op) = delete;
            Operation& operator=(Operation const&) = delete;

            // Returns the id of the thread currently executing this operation.
            std::thread::id thread_id() const noexcept
            {
                return m_thread_id;
            }

            // Returns the current status of this operation.
            OperationStatus status() const noexcept
            {
                return m_status;
            }

            // Returns true if this operation is currently scheduled, else false.
            bool is_scheduled() const noexcept
            {
                return m_is_scheduled;
            }

        private:
            // The id of the thread currently executing this operation.
            std::thread::id m_thread_id;

            // The current status of this operation.
            OperationStatus m_status;

            // Conditional variable that can be used to pause the execution of this operation.
            std::condition_variable m_cv;

            // True if this operation is currently scheduled, else false.
            bool m_is_scheduled;

            // Set of dependencies that must get satisfied before this operation can resume executing.
            std::vector<std::function<bool()>> m_dependencies;

            // The id of the resource that this operation is waiting for, if any.
            std::optional<size_t> m_dependent_resource_id;

            // The count of child operations created by this operation.
            size_t m_child_op_count;

            // Sets a callback that returns true when a dependency has been satisfied.
            void set_dependency_callback(std::function<bool()> callback)
            {
                m_dependencies.push_back(callback);
            }

            // Unblocks the operation if its dependencies have been satisfied.
            bool try_unblock()
            {
                size_t num_satisfied = 0;
                for (size_t index = 0; index < m_dependencies.size(); ++index)
                {
                    bool is_satisfied = m_dependencies[index]();
                    if (is_satisfied)
                    {
                        num_satisfied++;
                        if (m_status == OperationStatus::BlockedOnWaitAny)
                        {
                            break;
                        }
                    }
                }

                if ((num_satisfied > 0 && m_status == OperationStatus::BlockedOnWaitAny) ||
                    (num_satisfied == m_dependencies.size() && m_status == OperationStatus::BlockedOnWaitAll))
                {
                    m_dependencies.clear();
                    m_status = OperationStatus::Enabled;
                    return true;
                }

                return false;
            }

            // Returns the next creation sequence vector of the specified parent operation.
            std::vector<size_t> get_next_creation_seq(size_t op_id, Operation* const parent_op)
            {
                std::vector<size_t> creation_seq;
                if (op_id == 0)
                {
                    // If this is the root operation, then the creation sequence only contains
                    // the root operation itself.
                    creation_seq.push_back(0);
                }
                else
                {
                    creation_seq.assign(parent_op->m_creation_seq.begin(), parent_op->m_creation_seq.end());
                    creation_seq.push_back(parent_op->m_child_op_count);
                    parent_op->m_child_op_count++;
                }

                return creation_seq;
            }

            // Returns the hash of the creation sequence vector.
            size_t get_seq_hash() const noexcept
            {
                // Iterate the creation sequence vector and create a low collision rate hash.
                size_t hash = m_creation_seq.size();
                for(auto seq : m_creation_seq) {
                    seq = ((seq >> 16) ^ seq) * 0x45d9f3b;
                    seq = ((seq >> 16) ^ seq) * 0x45d9f3b;
                    seq = (seq >> 16) ^ seq;
                    hash ^= seq + 0x9e3779b9 + (hash << 6) + (hash >> 2);
                }

                return hash;
            }
        };

        // Data structure that maintains a set of controlled operations and splits them into
        // an enabled and a disabled sub-set that is used when taking scheduling decisions.
        class Operations
        {
        public:
            Operations(const Logger& logger) noexcept :
                m_enabled_operations_size(0),
                m_disabled_operations_size(0),
                m_logger(logger)
            {
            }

            Operations(Operations&& op) = delete;
            Operations(Operations const&) = delete;

            Operations& operator=(Operations&& op) = delete;
            Operations& operator=(Operations const&) = delete;

            const Operation* operator[](size_t index) const
            {
                return m_operations[index];
            }

            void insert(const Operation* op)
            {
                m_logger.log_debug("[st::engine] inserting operation '", op->id, "'.");
                log_debug("pre-insert");
                m_operations.push_back(op);
                m_enabled_operations_size++;
                if (m_operations.size() != m_enabled_operations_size)
                {
                    swap(m_operations.size() - 1, m_enabled_operations_size - 1);
                }

                log_debug("post-insert");
            }

            void remove(size_t op_id)
            {
                m_logger.log_debug("[st::engine] removing operation '", op_id, "'.");
                log_debug("pre-remove");

                bool found = false;
                size_t index;
                if (find_index(op_id, 0, m_enabled_operations_size, index))
                {
                    m_enabled_operations_size--;
                    found = true;
                }
                else if (find_index(op_id, m_enabled_operations_size, m_operations.size(), index))
                {
                    m_disabled_operations_size--;
                    found = true;
                }

                if (found)
                {
                    log_debug_swap("remove", index);
                    swap(index, m_enabled_operations_size);
                    swap(m_enabled_operations_size, m_operations.size() - 1);
                    m_operations.pop_back();
                }

                log_debug("post-remove");
            }

            void enable(size_t op_id)
            {
                m_logger.log_debug("[st::engine] enabling operation '", op_id, "'.");
                log_debug("pre-enable");

                size_t index;
                if (find_index(op_id, m_enabled_operations_size, m_operations.size(), index))
                {
                    log_debug_swap("enable", index);
                    swap(index, m_enabled_operations_size);
                    m_enabled_operations_size++;
                    m_disabled_operations_size--;
                }

                log_debug("post-enable");
            }

            void disable(size_t op_id)
            {
                m_logger.log_debug("[st::engine] disabling operation '", op_id, "'.");
                log_debug("pre-disable");

                size_t index;
                if (find_index(op_id, 0, m_enabled_operations_size, index))
                {
                    m_enabled_operations_size--;
                    m_disabled_operations_size++;
                    log_debug_swap("disable", index);
                    swap(index, m_enabled_operations_size);
                }

                log_debug("post-disable");
            }

            bool is_enabled(size_t op_id) const
            {
                size_t index;
                return find_index(op_id, 0, m_enabled_operations_size, index);
            }

            const Operation* get_if_enabled(size_t op_id) const
            {
                size_t index;
                if (find_index(op_id, 0, m_enabled_operations_size, index))
                {
                    return m_operations[index];
                }

                return nullptr;
            }

            size_t size(bool is_enabled = true) const noexcept
            {
                return is_enabled ? m_enabled_operations_size : m_disabled_operations_size;
            }

            void clear()
            {
                m_operations.clear();
                m_enabled_operations_size = 0;
                m_disabled_operations_size = 0;
            }

        private:
            std::vector<const Operation*> m_operations;
            size_t m_enabled_operations_size;
            size_t m_disabled_operations_size;

            // The logger used by the engine to log messages.
            const Logger& m_logger;

            bool find_index(size_t op_id, size_t start, size_t end, size_t& index) const
            {
                for (index = start; index < end; ++index)
                {
                    if (m_operations[index]->id == op_id)
                    {
                        return true;
                    }
                }

                return false;
            }

            void swap(size_t left, size_t right)
            {
                if (left != right)
                {
                    auto temp = m_operations[left];
                    m_operations[left] = m_operations[right];
                    m_operations[right] = temp;
                }
            }

            void log_debug(std::string action_type) const
            {
                if (m_logger.verbosity_level() == VerbosityLevel::Debug)
                {
                    m_logger.log_debug("[st::engine] ", action_type, " total/enabled/disabled: ", m_operations.size(),
                        "/", m_enabled_operations_size, "/", m_disabled_operations_size, ".");

                    std::cout << "[st::engine] enabled: ";
                    for (size_t index = 0; index < m_enabled_operations_size; ++index)
                    {
                        if (index == 0)
                        {
                            std::cout << m_operations[index]->id;
                        }
                        else
                        {
                            std::cout << ", " << m_operations[index]->id;
                        }
                    }

                    std::cout << std::endl;
                    std::cout << "[st::engine] disabled: ";
                    for (size_t index = m_enabled_operations_size; index < m_operations.size(); ++index)
                    {
                        if (index == m_enabled_operations_size)
                        {
                            std::cout << m_operations[index]->id;
                        }
                        else
                        {
                            std::cout << ", " << m_operations[index]->id;
                        }
                    }

                    std::cout << std::endl;
                }
            }

            void log_debug_swap(std::string type, size_t index) const
            {
                if (m_logger.verbosity_level() == VerbosityLevel::Debug)
                {
                    m_logger.log_debug("[st::engine] ", type, "-swap: ", index, "-", m_enabled_operations_size,
                        "-", m_disabled_operations_size, ".");
                }
            }
        };

        // Implements the xoroshiro pseudorandom number generator.
        class RandomGenerator
        {
        public:
            RandomGenerator() noexcept :
                m_x(5489),
                m_y(0)
            {
                next();
            }

            RandomGenerator(RandomGenerator&& strategy) = delete;
            RandomGenerator(RandomGenerator const&) = delete;

            RandomGenerator& operator=(RandomGenerator&& strategy) = delete;
            RandomGenerator& operator=(RandomGenerator const&) = delete;

            void seed(const size_t seed)
            {
                m_x = seed == 0 ? 5489 : seed;
                m_y = seed;
                next();
            }

            bool next_boolean()
            {
                return (next() & 1) == 0;
            }

            size_t next_integer(size_t max_value)
            {
                return next() % (max_value + 1);
            }

        private:
            static constexpr unsigned STATE_BITS = 8 * sizeof(size_t);
            static constexpr unsigned RESULT_BITS = 8 * sizeof(size_t);

            size_t m_x;
            size_t m_y;

            size_t next()
            {
                size_t r = m_x + m_y;
                m_y ^= m_x;
                m_x = rotl(m_x, 55) ^ m_y ^ (m_y << 14);
                m_y = rotl(m_y, 36);
                return r >> (STATE_BITS - RESULT_BITS);
            }

            static inline size_t rotl(const size_t m_x, const size_t k)
            {
                return (m_x << k) | (m_x >> (STATE_BITS - k));
            }
        };

#ifdef SYSTEST_AS_LIBRARY
        // Sets the thread local state of the currently executing controlled operation.
        SYSTEST_API void set_thread_local_operation_state(size_t op_id);

        // Removes the thread local state of the currently executing controlled operation.
        SYSTEST_API void remove_thread_local_operation_state(size_t op_id);

        // Returns the id of the currently executing controlled operation.
        SYSTEST_API std::optional<size_t> get_thread_local_executing_operation_id();
#else
        thread_local std::optional<size_t> tls_executing_op_id = std::nullopt;

        void set_thread_local_operation_state(size_t op_id)
        {
            tls_executing_op_id = op_id;
        }

        void remove_thread_local_operation_state(size_t op_id)
        {
            if (tls_executing_op_id.has_value() && tls_executing_op_id.value() == op_id)
            {
                tls_executing_op_id = std::nullopt;
            }
        }

        std::optional<size_t> get_thread_local_executing_operation_id()
        {
            return tls_executing_op_id;
        }
#endif
    } // namespace SystematicTesting::Runtime

    namespace Exploration
    {
        using namespace Runtime;

        // Represents an abstract nondeterministic choice during exploration.
        struct NondeterministicChoice
        {
            NondeterministicChoice() noexcept {}
            virtual ~NondeterministicChoice() = default;

            // Returns the choice in string format.
            virtual std::string to_string() const = 0;
        };

        // Represents an operation scheduling choice during exploration.
        struct OperationChoice : public NondeterministicChoice
        {
            // The id of this operation choice.
            const size_t op_id;

            // The creation sequence id of this operation choice.
            const size_t seq_id;

            OperationChoice(const Operation* op) noexcept :
                op_id(op->id),
                seq_id(op->seq_id)
            {
            }

            // Returns the choice in string format.
            std::string to_string() const override
            {
                return std::to_string(op_id);
            }
        };

        // Represents a boolean choice during exploration.
        struct BooleanChoice : public NondeterministicChoice
        {
            // The value of this boolean choice.
            const bool value;
            BooleanChoice(bool value) noexcept : value(value) {}

            // Returns the choice in string format.
            std::string to_string() const override
            {
                return Logger::format("bool(", value ? 1 : 0, ")");
            }
        };

        // Represents an integer choice during exploration.
        struct IntegerChoice : public NondeterministicChoice
        {
            // The value of this integer choice.
            const size_t value;
            IntegerChoice(size_t value) noexcept : value(value) {}

            // Returns the choice in string format.
            std::string to_string() const override
            {
                return Logger::format("int(", value, ")");
            }
        };

        // Data structure that maintains a set of controlled nondeterministic choices that
        // represent the explored execution path during a test iteration.
        class ExecutionPath
        {
        public:
            ExecutionPath() noexcept : m_path() {}
            ExecutionPath(ExecutionPath&& op) = delete;
            ExecutionPath(ExecutionPath const&) = delete;

            ExecutionPath& operator=(ExecutionPath&& op) = delete;
            ExecutionPath& operator=(ExecutionPath const&) = delete;

            // Returns the choice at the given index.
            const NondeterministicChoice* operator[](size_t index)
            {
                return m_path[index].get();
            }

            // Appends the specified operation choice.
            void append(const Operation* op)
            {
                m_path.push_back(std::make_unique<OperationChoice>(op));
            }

            // Appends the specified boolean choice.
            void append(bool value)
            {
                m_path.push_back(std::make_unique<BooleanChoice>(value));
            }

            // Appends the specified integer choice.
            void append(size_t value)
            {
                m_path.push_back(std::make_unique<IntegerChoice>(value));
            }

            // Resets the execution path.
            void reset()
            {
                m_path.clear();
            }

            // Returns the length of the execution path.
            size_t length() const
            {
                return m_path.size();
            }

            // Returns the execution path in a format that can be used for replaying.
            std::string to_replay_format() const
            {
                std::ostringstream result;
                for (size_t i = 0; i < m_path.size(); ++i)
                {
                    result << m_path[i]->to_string();
                    if (i < m_path.size() - 1)
                    {
                        result << ';';
                    }
                }

                return result.str();
            }

            // Returns the execution path as a string.
            std::string to_string() const
            {
                std::ostringstream result;
                for (size_t i = 0; i < m_path.size(); ++i)
                {
                    if (auto op_choice = dynamic_cast<OperationChoice*>(m_path[i].get()))
                    {
                        result << op_choice->seq_id;
                    }
                    else
                    {
                        result << m_path[i]->to_string();
                    }

                    if (i < m_path.size() - 1)
                    {
                        result << ';';
                    }
                }

                return result.str();
            }

        private:
            // The sequence of choices representing the execution path.
            std::vector<std::unique_ptr<NondeterministicChoice>> m_path;
        };

        // An abstract strategy for exploring the state and schedule space.
        class Strategy
        {
        public:
            Strategy(const Settings& settings, const Logger& logger) noexcept :
                m_type(settings.exploration_strategy()),
                m_execution_path(),
                m_iteration_seed(settings.random_seed()),
                m_random_generator(),
                m_logger(logger)
            {
            }

            // Prepares for the next iteration.
            virtual void prepare_next_iteration(size_t iteration) = 0;

            // Returns the next operation.
            virtual const Operation* next_operation(Operations& operations, const Operation* current) = 0;

            // Returns the next boolean choice.
            virtual bool next_boolean() = 0;

            // Returns the next integer choice between 0 and the specified inclusive max value.
            virtual size_t next_integer(size_t max_value) = 0;

            // Returns the execution path explored in the current iteration.
            const ExecutionPath& execution_path() const noexcept
            {
                return m_execution_path;
            }

            // Returns the random number generator.
            RandomGenerator& random_generator() noexcept
            {
                return m_random_generator;
            }

            // Returns the seed used in the current iteration.
            size_t random_seed() const noexcept
            {
                return m_iteration_seed;
            }

            // Returns the name of the strategy.
            std::string name() const noexcept
            {
                if (m_type == StrategyType::Prioritization)
                {
                    return "prioritization";
                }
                else if (m_type == StrategyType::Replay)
                {
                    return "replay";
                }

                return "random";
            }

            virtual ~Strategy() = default;

        protected:
            // The type of this strategy.
            StrategyType m_type;

            // The execution path explored in the current iteration.
            ExecutionPath m_execution_path;

            // The seed used by the current iteration.
            size_t m_iteration_seed;

            // The random value generator.
            RandomGenerator m_random_generator;

            // The logger used by the engine to log messages.
            const Logger& m_logger;

            // Records the specified operation choice in the execution path and returns its operation.
            const Operation* record_operation_choice(const Operation* operation)
            {
                m_execution_path.append(operation);
                return operation;
            }

            // Records the specified boolean choice in the execution path and returns its value.
            bool record_boolean_choice(bool value)
            {
                m_execution_path.append(value);
                return value;
            }

            // Records the specified integer choice in the execution path and returns its value.
            size_t record_integer_choice(size_t value)
            {
                m_execution_path.append(value);
                return value;
            }
        };

        // An exploration strategy that uses a uniform probability to choose actions.
        class RandomStrategy : public Strategy
        {
        public:
            RandomStrategy(const Settings& settings, const Logger& logger) noexcept :
                Strategy(settings, logger),
                m_scheduling_deviation_probability(settings.exploration_strategy_bound())
            {
            }

            RandomStrategy(RandomStrategy&& strategy) = delete;
            RandomStrategy(RandomStrategy const&) = delete;

            RandomStrategy& operator=(RandomStrategy&& strategy) = delete;
            RandomStrategy& operator=(RandomStrategy const&) = delete;

            // Prepares for the next iteration.
            void prepare_next_iteration(size_t iteration) override
            {
                if (iteration > 1)
                {
                    m_iteration_seed++;
                }

                m_random_generator.seed(m_iteration_seed);
                m_execution_path.reset();
            }

            // Returns the next operation.
            const Operation* next_operation(Operations& operations, const Operation* current) override
            {
                if (m_scheduling_deviation_probability < 100)
                {
                    bool is_current_enabled = false;
                    for (size_t idx = 0; idx < operations.size(); ++idx)
                    {
                        if (operations[idx]->id == current->id)
                        {
                            is_current_enabled = true;
                            break;
                        }
                    }

                    if (is_current_enabled && m_random_generator.next_integer(100) > m_scheduling_deviation_probability)
                    {
                        return current;
                    }
                }

                size_t index = m_random_generator.next_integer(operations.size() - 1);
                return record_operation_choice(operations[index]);
            }

            // Returns the next boolean choice.
            bool next_boolean() override
            {
                return record_boolean_choice(m_random_generator.next_boolean());
            }

            // Returns the next integer choice between 0 and the specified inclusive max value.
            size_t next_integer(size_t max_value) override
            {
                return record_integer_choice(m_random_generator.next_integer(max_value));
            }

        private:
            // The probability of deviating from the current operation if it is enabled.
            const size_t m_scheduling_deviation_probability;
        };

        // A probabilistic priority-based scheduling strategy.
        class PrioritizationStrategy : public Strategy
        {
            // The strategy is based on the PCT algorithm described in the following paper:
            // https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/asplos277-pct.pdf.
        public:
            PrioritizationStrategy(const Settings& settings, const Logger& logger) noexcept :
                Strategy(settings, logger),
                m_priority_change_bound(settings.exploration_strategy_bound()),
                m_prioritized_operations(),
                m_priority_change_points(),
                m_priority_change_points_count(0),
                m_max_priority_change_points(0)
            {
            }

            PrioritizationStrategy(PrioritizationStrategy&& strategy) = delete;
            PrioritizationStrategy(PrioritizationStrategy const&) = delete;

            PrioritizationStrategy& operator=(PrioritizationStrategy&& strategy) = delete;
            PrioritizationStrategy& operator=(PrioritizationStrategy const&) = delete;

            // Prepares for the next iteration.
            void prepare_next_iteration(size_t iteration) override
            {
                // The first iteration has no knowledge of the execution, so only initialize from the second
                // iteration and onwards. Note that although we could initialize the first length based on a
                // heuristic, its not worth it, as the strategy will typically explore thousands of iterations,
                // plus its also interesting to explore a schedule with no forced priority switch points.
                if (iteration > 1)
                {
                    m_prioritized_operations.clear();
                    m_priority_change_points.clear();

                    m_max_priority_change_points = std::max<size_t>(m_max_priority_change_points,
                        m_priority_change_points_count);
                    if (m_priority_change_bound > 0)
                    {
                        randomize_priority_change_points();
                    }

                    m_iteration_seed++;
                }

                m_random_generator.seed(m_iteration_seed);
                m_execution_path.reset();
                m_priority_change_points_count = 0;
            }

            // Returns the next operation.
            const Operation* next_operation(Operations& operations, const Operation* current) override
            {
                // Set the priority of any new operation groups.
                set_new_operation_priorities(operations, current);

                // Check if there are at least two operations that can be scheduled,
                // otherwise skip the priority changing logic.
                if (operations.size() > 1)
                {
                    // Try to change the priority of the highest-priority operation.
                    try_prioritize_next_operation(operations);
                }

                // Get the highest-priority operation id, or if there is only one operation, just return it.
                auto next_op = operations.size() > 1 ? get_operation_with_highest_priority(operations) : operations[0];
                return record_operation_choice(next_op);
            }

            // Returns the next boolean choice.
            bool next_boolean() override
            {
                return record_boolean_choice(m_random_generator.next_boolean());
            }

            // Returns the next integer choice between 0 and the specified inclusive max value.
            size_t next_integer(size_t max_value) override
            {
                return record_integer_choice(m_random_generator.next_integer(max_value));
            }

        private:
            // The max number of priority changes per iteration.
            const size_t m_priority_change_bound;

            // List representing the priorities of operations in the current iteration.
            // The highest-priority operation is at the head of the list.
            std::list<const Operation*> m_prioritized_operations;

            // Scheduling points in the current iteration where a priority change should occur.
            std::set<size_t> m_priority_change_points;

            // Number of potential priority change points in the current iteration.
            size_t m_priority_change_points_count;

            // Max number of potential priority change points across all iterations.
            size_t m_max_priority_change_points;

            // Sets a random priority to any new operations.
            void set_new_operation_priorities(Operations& operations, const Operation* current)
            {
                size_t previous_size = m_prioritized_operations.size();
                if (previous_size == 0)
                {
                    m_prioritized_operations.push_back(current);
                }

                // Randomize the priority of all new operations.
                for (size_t idx = 0; idx < operations.size(); ++idx)
                {
                    auto op = operations[idx];
                    auto op_it = std::find_if(m_prioritized_operations.begin(), m_prioritized_operations.end(),
                        [&](const Operation* next_op) { return next_op->id == op->id; });
                    if (op_it == m_prioritized_operations.end())
                    {
                        // Randomly choose a priority for this operation.
                        size_t index = m_random_generator.next_integer(m_prioritized_operations.size() - 1) + 1;
                        auto it = std::next(m_prioritized_operations.begin(), index);
                        m_prioritized_operations.insert(it, op);
                        m_logger.log_debug("[st::strategy] assigned priority '", index, "' to operation '", op->id, "'.");
                    }
                }

                log_debug_operation_priority_list(operations, previous_size);
            }

            // Reduces the priority of highest-priority operation, if the current scheduling
            // step has a priority change point.
            void try_prioritize_next_operation(Operations& operations)
            {
                if (m_priority_change_points.find(m_priority_change_points_count) != m_priority_change_points.end())
                {
                    // This scheduling step was chosen as a priority change point.
                    auto op = get_operation_with_highest_priority(operations);
                    auto op_it = std::find_if(m_prioritized_operations.begin(), m_prioritized_operations.end(),
                        [&](const Operation* next_op) { return next_op->id == op->id; });
                    if (op_it != m_prioritized_operations.end())
                    {
                        // Reduce the priority of the operation by moving it to the end of the list.
                        m_prioritized_operations.erase(op_it);
                        m_prioritized_operations.push_back(op);
                        m_logger.log_debug("[st::strategy] reduced the priority of operation '", op->id, "'.");
                    }
                }

                m_priority_change_points_count++;
            }

            // Returns the highest-priority operation id.
            const Operation* get_operation_with_highest_priority(Operations& operations)
            {
                for (auto next_op : m_prioritized_operations)
                {
                    if (operations.is_enabled(next_op->id))
                    {
                        return next_op;
                    }
                }

                return nullptr;
            }

            // Randomizes the number of priority changes for the next iteration up to the bound.
            void randomize_priority_change_points()
            {
                size_t priority_changes = m_random_generator.next_integer(m_priority_change_bound - 1) + 1;
                m_logger.log_debug("[st::strategy] assigned ", priority_changes, " priority changes.");
                std::vector<size_t> points = shuffle_range(m_max_priority_change_points);
                for (size_t idx = 0; idx < points.size() && idx < priority_changes; ++idx)
                {
                    m_priority_change_points.insert(points[idx]);
                }

                log_debug_priority_change_points();
            }

            // Shuffles the specified range.
            std::vector<size_t> shuffle_range(size_t max_value)
            {
                // Create range up to the max value.
                std::vector<size_t> points(max_value);
                std::iota(points.begin(), points.end(), 0);

                // Randomize the range using the Fisher-Yates algorithm.
                // See https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle.
                for (size_t idx = max_value - 1; idx >= 1; --idx)
                {
                    size_t index = m_random_generator.next_integer(idx);
                    std::swap(points[idx], points[index]);
                }

                return points;
            }

            // Log the operation group priority list, if debug is enabled.
            void log_debug_operation_priority_list(Operations& operations, size_t previous_size)
            {
                if (m_logger.verbosity_level() == VerbosityLevel::Debug && m_prioritized_operations.size() > previous_size)
                {
                    m_logger.log_debug("[st::strategy] updated operation priority list:");
                    int idx = 0;
                    for (auto op : m_prioritized_operations)
                    {
                        if (operations.is_enabled(op->id))
                        {
                            m_logger.log_debug("[st::strategy]   [", idx++, "] operation '", op->id, "' [enabled]");
                        }
                        else
                        {
                            m_logger.log_debug("[st::strategy]   [", idx++, "] operation '", op->id, "'");
                        }
                    }
                }
            }

            // Log the priority change points, if debug is enabled.
            void log_debug_priority_change_points()
            {
                if (m_logger.verbosity_level() == VerbosityLevel::Debug)
                {
                    if (m_priority_change_points.size() > 0)
                    {
                        m_logger.log_debug("[st::strategy] assigned priority change points:");
                        for (auto point : m_priority_change_points)
                        {
                            m_logger.log_debug("[st::strategy]   [", point, "]");
                        }
                    }
                    else
                    {
                        m_logger.log_debug("[st::strategy] assigned zero priority change points.");
                    }
                }
            }
        };

        // A replay strategy that can reproduce an execution from its sequence of choices.
        class ReplayStrategy : public Strategy
        {
        public:
            ReplayStrategy(const Settings& settings, const Logger& logger) noexcept :
                Strategy(settings, logger),
                m_trace(decode_trace(settings.replay_trace()))
            {
            }

            ReplayStrategy(ReplayStrategy&& strategy) = delete;
            ReplayStrategy(ReplayStrategy const&) = delete;

            ReplayStrategy& operator=(ReplayStrategy&& strategy) = delete;
            ReplayStrategy& operator=(ReplayStrategy const&) = delete;

            // Prepares for the next iteration.
            void prepare_next_iteration([[maybe_unused]] size_t iteration) override
            {
                m_execution_path.reset();
            }

            // Returns the next operation.
            const Operation* next_operation(Operations& operations, [[maybe_unused]] const Operation* current) override
            {
                std::string step = m_trace[m_execution_path.length()];
                size_t op_id = std::stoull(step);
                auto op = operations.get_if_enabled(op_id);
                if (op == nullptr)
                {
                    auto error = "unable to reproduce trace (expected operation id instead of '" + step + "')";
                    m_logger.log_error("[st::error] ", error, ".");
                    throw std::runtime_error(error);
                }

                return record_operation_choice(op);
            }

            // Returns the next boolean choice.
            bool next_boolean() override
            {
                std::string step = m_trace[m_execution_path.length()];
                if (step.size() <= 6 || step.substr(0, 5) != "bool(" || step.back() != ')')
                {
                    auto error = "unable to reproduce trace (expected boolean choice instead of '" + step + "')";
                    m_logger.log_error("[st::error] ", error, ".");
                    throw std::runtime_error(error);
                }

                bool choice = std::stoi(step.substr(5, step.size() - 5));
                return record_boolean_choice(choice);
            }

            // Returns the next integer choice between 0 and the specified inclusive max value.
            size_t next_integer([[maybe_unused]] size_t max_value) override
            {
                std::string step = m_trace[m_execution_path.length()];
                if (step.size() <= 5 || step.substr(0, 4) != "int(" || step.back() != ')')
                {
                    auto error = "unable to reproduce trace (expected integer choice instead of '" + step + "')";
                    m_logger.log_error("[st::error] ", error, ".");
                    throw std::runtime_error(error);
                }

                size_t choice = std::stoul(step.substr(4, step.size() - 5));
                return record_integer_choice(choice);
            }

        private:
            // The sequence of nondeterministic choices to reproduce an execution.
            std::vector<std::string> m_trace;

            // Decodes the specified trace into a sequence of choices.
            std::vector<std::string> decode_trace(const std::string& trace)
            {
                // Split the string into tokens using the ; delimiter.
                std::vector<std::string> choices;
                std::stringstream stream(trace);
                std::string choice;
                while (std::getline(stream, choice, ';'))
                {
                    choices.push_back(choice);
                }

                return choices;
            }
        };

        static std::unique_ptr<Strategy> create_strategy(const Settings& settings, const Logger& logger) noexcept
        {
            if (settings.exploration_strategy() == StrategyType::Prioritization)
            {
                return std::make_unique<PrioritizationStrategy>(settings, logger);
            }
            else if (settings.exploration_strategy() == StrategyType::Replay)
            {
                return std::make_unique<ReplayStrategy>(settings, logger);
            }

            return std::make_unique<RandomStrategy>(settings, logger);
        }
    } // namespace SystematicTesting::Exploration

    // A systematic test engine that controls the lifetime of concurrent operations
    // and schedules them in a serialized way to explore their interleavings.
    class TestEngine
    {
    public:
        TestEngine(Settings settings) noexcept :
            m_settings(settings),
            m_logger(m_settings.verbosity_level()),
            m_strategy(Exploration::create_strategy(m_settings, m_logger)),
            m_report(m_strategy->name()),
            m_operation_map(),
            m_resource_map(),
            m_operations(m_logger),
            m_threads(),
            m_detached_threads(),
            m_global_detached_threads(),
            m_uncontrolled_thread_ids(),
            m_op_creation_sequence_ids(),
            m_state_hashing_functions(),
            m_op_id_count(0),
            m_resource_id_count(0),
            m_iteration_count(0),
            m_status(Status::Detached),
            m_pending_operations_count(0),
            m_pending_operations_cv(),
            m_lock(),
            m_clock()
        {
            m_logger.log_info("[st::engine] initialized the test engine.");
        }

        // Prepares the engine for a new test iteration. This allows optional test initialization code to execute
        // without the execution being controlled until the engine is attached.
        void prepare()
        {
            std::unique_lock<std::mutex> lock(m_lock);
            m_clock = std::chrono::steady_clock::now();
            m_iteration_count++;
            m_logger.log_info("[st::engine] preparing the test engine for iteration ", m_iteration_count, ".");

            if (m_status != Status::Detached)
            {
                throw std::runtime_error("the test engine is not detached");
            }

            m_status = Status::Preparing;
            m_strategy->prepare_next_iteration(m_iteration_count);
            m_logger.log_debug("[st::engine] using random seed '", m_strategy->random_seed(), "'.");

            // Update the test report.
            m_report.m_iterations = m_iteration_count;
        }

        // Attaches the engine to start a new test iteration. When attached, the engine takes control of the execution
        // to explore interleavings and other sources of nondeterminism. It creates a root operation with id '0' and
        // associates it with the caller thread.
        void attach()
        {
            // Wait for any detached threads during initialization to terminate.
            wait_threads(m_detached_threads, false);
            m_detached_threads.clear();

            // Capture the runtime of the initialization phase during the test iteration.
            m_report.m_elapsed_unattached_time += std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - m_clock).count();

            std::unique_lock<std::mutex> lock(m_lock);
            m_logger.log_info("[st::engine] attaching the test engine to iteration ", m_iteration_count, ".");
            if (m_status != Status::Preparing)
            {
                throw Exceptions::TestEngineDetachedError();
            }

            m_status = Status::Attached;

            // Create and start the root operation with id '0'.
            size_t op_id = get_next_operation_id();
            auto op = create_operation(op_id);
            start_operation(op, lock);
        }

        // Schedules the specified function to execute on a controlled thread.
        void schedule(std::function<void()> func)
        {
            std::unique_lock<std::mutex> lock(m_lock);
            if (m_status == Status::Attached)
            {
                auto current_op = get_executing_operation_if(m_status == Status::Attached);
                m_logger.log_debug("[st::engine] scheduling operation from ", current_op == nullptr ? "un" : "",
                    "controlled thread '", std::this_thread::get_id(), "'.");

                size_t op_id = get_next_operation_id();
                auto op = create_operation(op_id, current_op);
                m_threads.emplace_back(std::thread(std::bind(&TestEngine::execute, this, func, op)));

                if (current_op != nullptr)
                {
                    // Try explore a scheduling decision where either the current operation or the operation
                    // it has been waiting for gets scheduled next.
                    schedule_next_operation(current_op, lock);
                }
            }
            else if (m_status == Status::Preparing || m_status == Status::Detaching)
            {
                m_logger.log_debug("[st::engine] scheduling uncontrolled operation from detached thread '",
                    std::this_thread::get_id(), "'.");
                m_detached_threads.emplace_back(std::thread(func));
            }
            else if (m_status == Status::Detached)
            {
                m_logger.log_debug("[st::engine] scheduling uncontrolled operation from detached thread '",
                    std::this_thread::get_id(), "'.");
                m_global_detached_threads.emplace_back(std::thread(func));
            }
        }

        // Creates a new operation and returns its unique id, or nullopt if the engine is detached
        // or the current thread is not controlled.
        std::optional<size_t> create_next_operation()
        {
            std::unique_lock<std::mutex> lock(m_lock);
            if (auto current_op = get_executing_operation_if(m_status == Status::Attached))
            {
                size_t op_id = get_next_operation_id();
                create_operation(op_id, current_op);
                return op_id;
            }

            m_logger.log_debug("[st::engine] unable to create next operation from detached thread '",
                    std::this_thread::get_id(), "'.");
            return std::nullopt;
        }

        // Starts executing the operation with the specified id.
        void start_operation(size_t op_id)
        {
            std::unique_lock<std::mutex> lock(m_lock);
            auto op = get_operation(op_id);
            if (op == nullptr)
            {
                m_logger.log_error("[st::engine] unable to start operation '", op_id, "' as it does not exist.");
                throw Exceptions::OperationNotFoundError(op_id);
            }

            start_operation(op, lock);
        }

        // Pauses the currently executing operation until the specified condition gets satisfied.
        void pause_operation_until_condition(std::function<bool()> condition)
        {
            std::unique_lock<std::mutex> lock(m_lock);
            if (auto current_op = get_executing_operation_if(m_status == Status::Attached))
            {
                m_logger.log_debug("[st::engine] operation '", current_op->id, "' on thread '",
                    std::this_thread::get_id(), "' is waiting for condition to get satisfied.");
                current_op->set_dependency_callback(condition);
                current_op->m_status = Runtime::OperationStatus::BlockedOnWaitAll;
                m_operations.disable(current_op->id);
                schedule_next_operation(current_op, lock);
            }
            else
            {
                m_logger.log_debug("[st::engine] unable to pause detached thread '", std::this_thread::get_id(),
                    "' until condition gets satisfied.");
            }
        }

        // Schedules the next operation, which can include the currently executing operation.
        // Only operations that are not blocked nor completed can be scheduled.
        void schedule_next_operation()
        {
            std::unique_lock<std::mutex> lock(m_lock);
            schedule_next_operation(lock);
        }

        // Completes the currently executing operation and schedules the next operation.
        void complete_current_operation()
        {
            std::unique_lock<std::mutex> lock(m_lock);
            if (auto current_op = get_executing_operation_if(m_status == Status::Attached))
            {
                complete_operation(current_op, true, lock);
            }
            else
            {
                m_logger.log_debug("[st::engine] unable to complete an operation from detached thread '",
                    std::this_thread::get_id(), "'.");
            }
        }

        // Returns the id of the controlled operation executing in the current thread, or nullopt if
        // the engine is not attached or the current thread is not controlled.
        std::optional<size_t> current_operation_id()
        {
            std::unique_lock<std::mutex> lock(m_lock);
            if (auto current_op = get_executing_operation_if(m_status == Status::Attached))
            {
                return current_op->id;
            }
            else
            {
                return std::nullopt;
            }
        }

        // Creates a new resource and returns its unique id, or nullopt if the engine is detached.
        std::optional<size_t> create_next_resource()
        {
            // We allow creating resources either when the engine is attached or when it is
            // preparing for a new iteration.
            std::unique_lock<std::mutex> lock(m_lock);
            if (m_status == Status::Preparing || m_status == Status::Attached)
            {
                size_t resource_id = get_next_resource_id();
                create_resource(resource_id);
                return resource_id;
            }

            return std::nullopt;
        }

        // Acquires the resource with the specified id.
        void acquire_resource(size_t resource_id)
        {
            std::unique_lock<std::mutex> lock(m_lock);
            if (auto current_op = get_executing_operation_if(m_status == Status::Attached))
            {
                acquire_resource(resource_id, current_op);
            }
            else
            {
                m_logger.log_debug("[st::engine] unable to acquire resource '", resource_id,
                    "' from detached thread '", std::this_thread::get_id(), "'.");
            }
        }

        // Waits the resource with the specified id to become available and schedules the next operation.
        void wait_resource(size_t resource_id)
        {
            std::unique_lock<std::mutex> lock(m_lock);
            if (auto current_op = get_executing_operation_if(m_status == Status::Attached))
            {
                wait_resource(resource_id, current_op, lock);
            }
            else
            {
                m_logger.log_debug("[st::engine] unable to wait resource '", resource_id,
                    "' from detached thread '", std::this_thread::get_id(), "'.");
            }
        }

        // Tries to release the resource with the specified id from the currently executing operation.
        // Returns true if the resource has no more owners and is released, else false.
        bool try_release_resource(size_t resource_id)
        {
            std::unique_lock<std::mutex> lock(m_lock);
            if (auto current_op = get_executing_operation_if(m_status == Status::Attached))
            {
                return try_release_resource(resource_id, current_op);
            }
            else
            {
                m_logger.log_debug("[st::engine] unable to release resource '", resource_id,
                    "' from detached thread '", std::this_thread::get_id(), "'.");
            }

            return false;
        }

        // Checks if the resource with the specified id is owned by the current operation.
        bool is_resource_owned_by_current_operation(size_t resource_id)
        {
            std::unique_lock<std::mutex> lock(m_lock);
            if (auto current_op = get_executing_operation_if(m_status == Status::Attached))
            {
                auto it = m_resource_map.find(resource_id);
                if (it != m_resource_map.end())
                {
                    std::map<size_t, size_t>& owner_ops = std::get<0>(it->second);
                    if (owner_ops.find(current_op->id) != owner_ops.end())
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        // Deletes the controlled resource with the specified id.
        void delete_resource(size_t resource_id)
        {
            // We allow deleting resources either when the engine is attached or when it is
            // preparing for a new iteration. All created resources will be automatically
            // deleted when the engine is detached.
            std::unique_lock<std::mutex> lock(m_lock);
            if (m_status == Status::Preparing || m_status == Status::Attached)
            {
                if (m_resource_map.find(resource_id) == m_resource_map.end())
                {
                    m_logger.log_error("[st::error] unable to delete resource '", resource_id,
                        "' from thread '", std::this_thread::get_id(), "' as it does not exist.");
                    throw Exceptions::ResourceNotFoundError(resource_id);
                }

                m_logger.log_exhaustive("[st::engine] deleted resource '", resource_id,
                    "' from thread '", std::this_thread::get_id(), "'.");
                m_resource_map.erase(resource_id);
            }
        }

        // Returns a controlled boolean value.
        bool choose_boolean()
        {
            std::unique_lock<std::mutex> lock(m_lock);
            if (get_executing_operation_if(m_status == Status::Attached) != nullptr)
            {
                bool value = m_strategy->next_boolean();
                m_logger.log_info("[st::engine] selected the random boolean '", value, "'.");
                return value;
            }
            else
            {
                return m_strategy->random_generator().next_boolean();
            }
        }

        // Returns a controlled integer value between 0 and the specified inclusive max value.
        size_t choose_integer(size_t max_value)
        {
            std::unique_lock<std::mutex> lock(m_lock);
            if (get_executing_operation_if(m_status == Status::Attached) != nullptr)
            {
                size_t value = m_strategy->next_integer(max_value);
                m_logger.log_info("[st::engine] selected the random integer '", value, "'.");
                return value;
            }
            else
            {
                return m_strategy->random_generator().next_integer(max_value);
            }
        }

        // Registers the specified state hashing function for the current iteration.
        void register_state_hashing_function(std::function<size_t()> func)
        {
            std::unique_lock<std::mutex> lock(m_lock);
            m_state_hashing_functions.push_back(func);
        }

        // Notifies the engine that an assertion has failed.
        void notify_assertion_failure()
        {
            notify_assertion_failure("an assertion failure was reported");
        }

        // Notifies the engine that an assertion has failed with the specified error.
        void notify_assertion_failure(std::string error)
        {
            std::unique_lock<std::mutex> lock(m_lock);
            m_logger.log_error("[st::error] ", error, ".");
            detach(true, lock);
        }

        // Returns true if the currently executing thread is attached to the engine.
        bool is_attached()
        {
            std::unique_lock<std::mutex> lock(m_lock);
            return get_executing_operation_if(m_status == Status::Attached) != nullptr;
        }

        // Returns true if the specified resource and the currently executing thread
        // are both attached to the engine.
        bool is_resource_attached(std::optional<size_t> resource_id)
        {
            std::unique_lock<std::mutex> lock(m_lock);
            bool is_attached = false;
            if (auto current_op = get_executing_operation_if(m_status == Status::Attached))
            {
                if (resource_id.has_value())
                {
                    is_attached = true;
                }
                else
                {
                    m_logger.log_debug("[st::engine] unable to access resource from operation '",
                        current_op->id, "' on thread '", std::this_thread::get_id(), "'.");
                }
            }

            return is_attached;
        }

        // Returns the immutable settings used to configure the engine.
        const Settings& settings() const noexcept
        {
            return m_settings;
        }

        // Returns the random seed used in the current iteration.
        size_t random_seed() noexcept
        {
            std::unique_lock<std::mutex> lock(m_lock);
            return m_strategy->random_seed();
        }

        // Returns a report with exploration statistics and coverage information.
        TestReport report()
        {
            std::unique_lock<std::mutex> lock(m_lock);
            return m_report;
        }

        // Logs the specified message.
        template<class... Args>
        void log(VerbosityLevel level, const Args&... args)
        {
            std::unique_lock<std::mutex> lock(m_lock);
            if (level >= VerbosityLevel::Info)
            {
                m_logger.log_info(args...);
            }
            else if (level >= VerbosityLevel::Debug)
            {
                m_logger.log_debug(args...);
            }
        }

        // Detaches the engine. This should be invoked at the end of a test iteration. It
        // completes the root operation with id '0' and waits until all threads created
        // during this iteration complete.
        void detach()
        {
            std::unique_lock<std::mutex> lock(m_lock);
            detach(false, lock);
        }

        virtual ~TestEngine()
        {
            {
                std::unique_lock<std::mutex> lock(m_lock);
                m_logger.log_info("[st::engine] disposing the test engine from thread '",
                    std::this_thread::get_id(), "'.");

                // Detach the engine if it is still attached. This can happen if an iteration
                //terminated early, for example due to an assertion failure.
                detach(false, lock);
                m_status = Status::Disposed;
            }

            wait_threads(m_global_detached_threads, false);
            m_logger.log_info("[st::engine] disposed the test engine from thread '",
                std::this_thread::get_id(), "'.");
        }

    private:
        // The status of the engine.
        enum class Status
        {
            Detached = 0,
            Attached,
            Preparing,
            Detaching,
            Disposed
        };

        // Settings that configure the program exploration.
        Settings m_settings;

        // Used for logging messages.
        Logger m_logger;

        // Strategy for exploring execution paths in the attached program.
        std::unique_ptr<Exploration::Strategy> m_strategy;

        // Report containing exploration statistics and coverage information.
        TestReport m_report;

        // Map from unique controlled operation ids to operations.
        std::map<size_t, std::unique_ptr<Runtime::Operation>> m_operation_map;

        // Map from unique controlled resource ids to a tuple that maintains the current set
        // of resource owners and the current set of any blocked operations.
        std::map<size_t, std::tuple<std::map<size_t, size_t>, std::set<size_t>>> m_resource_map;

        // Set of enabled and disabled controlled operation ids.
        Runtime::Operations m_operations;

        // Threads that execute controlled operations.
        std::vector<std::thread> m_threads;

        // Threads created during the current iteration and are known to be detached to the engine.
        std::vector<std::thread> m_detached_threads;

        // Threads that are known to be detached to the engine and do not correspond
        // to any particular test iteration.
        std::vector<std::thread> m_global_detached_threads;

        // Set of thread ids that are known to be uncontrolled by the engine.
        std::set<std::thread::id> m_uncontrolled_thread_ids;

        // Set of encountered operation creation sequence ids.
        std::set<size_t> m_op_creation_sequence_ids;

        // Functions for computing the state hash of the program.
        std::vector<std::function<size_t()>> m_state_hashing_functions;

        // Monotonically increasing counter of controlled operation identifiers.
        std::atomic_size_t m_op_id_count;

        // Monotonically increasing counter of resource identifiers.
        std::atomic_size_t m_resource_id_count;

        // The test iteration count.
        size_t m_iteration_count;

        // The current status of the engine.
        Status m_status;

        // Count of newly created operations that have not started executing yet.
        size_t m_pending_operations_count;

        // Conditional variable that can be used to wait for pending operations.
        std::condition_variable m_pending_operations_cv;

        // Lock that synchronizes access to the engine.
        std::mutex m_lock;

        // Clock for measuring elapsed time during testing.
        std::chrono::steady_clock::time_point m_clock;

        // Executes the specified function in the scope of a controlled operation.
        void execute(std::function<void()>& func, Runtime::Operation* const current_op)
        {
            std::unique_lock<std::mutex> lock(m_lock);
            try
            {
                // First, notify the engine that a new operation has started.
                start_operation(current_op, lock);

                // Next, execute the function without holding the engine lock.
                lock.unlock();
                func();
                lock.lock();

                // Finally, notify the engine that the operation has completed, which will
                // then schedule the next enabled operation, if there is any.
                complete_operation(current_op, true, lock);
            }
            catch (const Exceptions::TestEngineDetachedError&)
            {
                m_logger.log_debug("[st::engine] terminated operation '", current_op->id, "' on thread '",
                    std::this_thread::get_id(), "' as the test engine was detached.");
            }
            catch (...)
            {
                m_logger.log_error("[st::error] operation '", current_op->id, "' on thread '",
                    std::this_thread::get_id(), "' threw an unhandled exception.");
                detach(true, lock);
                throw;
            }
        }

        // Creates a new operation with the specified id.
        Runtime::Operation* create_operation(size_t op_id, Runtime::Operation* const creator_op = nullptr)
        {
            if (m_operation_map.find(op_id) != m_operation_map.end())
            {
                m_logger.log_error("[st::error] unable to create operation '", op_id, "' from thread '",
                    std::this_thread::get_id(), "' as it already exists.");
                throw Exceptions::OperationAlreadyExistsError(op_id);
            }

            // If no parent operation is found, and this is not the root operation,
            // then assign the root operation as the parent operation. This is just
            // an approximation that is applied in the case of uncontrolled threads.
            auto parent_op = creator_op == nullptr && op_id != 0 ? get_operation(0) : creator_op;
            size_t iteration = parent_op != nullptr ? parent_op->iteration : m_iteration_count;

            auto result = m_operation_map.insert(std::pair<size_t, std::unique_ptr<Runtime::Operation>>(
                op_id, std::make_unique<Runtime::Operation>(op_id, creator_op, iteration)));
            auto op = result.first->second.get();
            m_op_creation_sequence_ids.insert(op->seq_id);
            if (m_operation_map.size() == 1)
            {
                // This is the first operation, so schedule it.
                op->m_is_scheduled = true;
            }

            // Increment the count of created operations that have not yet started executing.
            m_pending_operations_count++;

            m_logger.log_info("[st::engine] created operation '", op_id, "' with sequence id '", op->seq_id,
                "' from thread '", std::this_thread::get_id(), "'.");
            return op;
        }

        // Starts executing the operation with the specified id.
        void start_operation(Runtime::Operation* const current_op, std::unique_lock<std::mutex>& lock)
        {
            if (m_status == Status::Attached)
            {
                // Set the necessary thread local state of the thread executing this operation.
                Runtime::set_thread_local_operation_state(current_op->id);

                m_logger.log_info("[st::engine] started operation '", current_op->id, "' on thread '",
                    std::this_thread::get_id(), "'.");
                current_op->m_thread_id = std::this_thread::get_id();
                current_op->m_status = Runtime::OperationStatus::Enabled;
                m_operations.insert(current_op);

                if (m_pending_operations_count == 0)
                {
                    // This is defensive code that should normally never happen, unless there is a bug
                    // in the engine or instrumentation code.
                    std::string error = Logger::format("unable to start operation '", current_op->id,
                        "' when there are no newly created operations that have not started yet");
                    m_logger.log_error("[st::error] ", error, ".");
                    throw Exceptions::InstrumentationError(error);
                }

                if (--m_pending_operations_count == 0)
                {
                    // All pending operations have started executing, so release any blocked operation.
                    m_pending_operations_cv.notify_one();
                }

                pause_operation(current_op, lock);
            }
            else
            {
                m_logger.log_debug("[st::engine] unable to start operation '", current_op->id, "' on detached thread '",
                    std::this_thread::get_id(), "'.");
            }
        }

        // Pauses the execution of the specified currently executing operation.
        void pause_operation(Runtime::Operation* const current_op, std::unique_lock<std::mutex>& lock)
        {
            if (current_op->m_status != Runtime::OperationStatus::Completed)
            {
                while (!current_op->m_is_scheduled && m_status == Status::Attached)
                {
                    m_logger.log_debug("[st::engine] pausing thread '", std::this_thread::get_id(),
                        "' until operation '", current_op->id, "' is scheduled.");
                    current_op->m_cv.wait(lock);
                    m_logger.log_debug("[st::engine] resuming thread '", std::this_thread::get_id(),
                        "' as operation '", current_op->id, "' was scheduled.");
                }
            }
        }

        // Completes the specified currently executing operation and optionally schedules the next operation.
        void complete_operation(Runtime::Operation* const current_op, bool schedule_next_op, std::unique_lock<std::mutex>& lock)
        {
            if (m_status == Status::Attached)
            {
                m_logger.log_info("[st::engine] completed operation '", current_op->id, "' on thread '",
                    std::this_thread::get_id(), "'.");
                current_op->m_status = Runtime::OperationStatus::Completed;
                m_operations.remove(current_op->id);

                // Remove the thread local state of the thread that executed this operation.
                Runtime::remove_thread_local_operation_state(current_op->id);

                if (schedule_next_op)
                {
                    schedule_next_operation(current_op, lock);
                }
            }
            else
            {
                m_logger.log_debug("[st::engine] unable to complete operation '", current_op->id, "' on detached thread '",
                    std::this_thread::get_id(), "'.");
            }
        }

        // Schedules the next operation, which can include the currently executing operation.
        // Only operations that are not blocked nor completed can be scheduled.
        void schedule_next_operation(std::unique_lock<std::mutex>& lock)
        {
            if (auto current_op = get_executing_operation_if(m_status == Status::Attached))
            {
                schedule_next_operation(current_op, lock);
            }
            else
            {
                m_logger.log_debug("[st::engine] cannot schedule operations from detached thread '",
                    std::this_thread::get_id(), "'.");
            }
        }

        // Schedules the next operation, which can include the currently executing operation.
        // Only operations that are not blocked nor completed can be scheduled.
        void schedule_next_operation(Runtime::Operation* const current_op, std::unique_lock<std::mutex>& lock)
        {
            if (!current_op->is_scheduled())
            {
                // This is defensive code that should normally never happen, unless there is a bug
                // in the engine or instrumentation code.
                std::string error = Logger::format("operation '", current_op->id, "' is executing on thread '",
                    std::this_thread::get_id(), "' without having been scheduled by the test engine");
                m_logger.log_error("[st::error] ", error, ".");
                throw Exceptions::InstrumentationError(error);
            }

            // Pause this thread until all recently created operations have started to avoid
            // race conditions between operation creation and operation start.
            while (m_pending_operations_count > 0)
            {
                m_logger.log_info("[st::engine] pausing thread '", std::this_thread::get_id(), "' until '",
                    m_pending_operations_count, "' pending operations start executing.");
                m_pending_operations_cv.wait(lock);
            }

            // Try to enable any operations with satisfied dependencies before asking the
            // engine to choose the next one to schedule.
            if (!try_enable_operations_with_satisfied_dependencies(lock))
            {
                // Check if the execution has deadlocked, and if yes fail.
                if (is_deadlocked())
                {
                    throw Exceptions::DeadlockError();
                }

                m_logger.log_info("[st::engine] path explored.");
                return;
            }

            // Compute the program state hash.
            size_t hash = get_current_program_state_hash();
            m_logger.log_debug("[st::engine] reached state '", hash, "' on thread '",
                std::this_thread::get_id(), "'.");
            m_report.m_visited_states.insert(hash);

            // Ask the strategy for the next operation to schedule.
            auto next_op = const_cast<Runtime::Operation*>(m_strategy->next_operation(m_operations, current_op));
            m_logger.log_info("[st::engine] scheduling operation '", next_op->id,
                "' (previous was '", current_op->id, "').");
            if (current_op->id != next_op->id)
            {
                // Resume the execution of the next operation.
                next_op->m_is_scheduled = true;
                next_op->m_cv.notify_one();

                // Pause the execution of the current operation.
                current_op->m_is_scheduled = false;
                pause_operation(current_op, lock);
            }
        }

        // Tries to enable any operations that have their dependencies satisfied. It returns
        // true if there is at least one operation enabled, else false.
        bool try_enable_operations_with_satisfied_dependencies(std::unique_lock<std::mutex>& lock)
        {
            m_logger.log_debug("[st::engine] enabling operations with satisfied dependencies.");

            size_t attempt = 0;
            size_t max_attempts = 10;
            while (true)
            {
                size_t enabled_index = m_operations.size();
                size_t total_size = enabled_index + m_operations.size(false);
                for (size_t index = enabled_index; index < total_size; ++index)
                {
                    auto op = const_cast<Runtime::Operation*>(m_operations[index]);
                    if (op->try_unblock())
                    {
                        m_logger.log_debug("[st::engine] operation '", op->id, "' is enabled.");
                        m_operations.enable(op->id);
                    }
                    else
                    {
                        m_logger.log_debug("[st::engine] operation '", op->id, "' is disabled.");
                    }
                }

                // TODO: this is very naive for now, need to implement better heuristic from C# Coyote.
                // Heuristics for handling a partially controlled execution.
                if (m_settings.is_partially_controlled_concurrency_allowed() && ++attempt < max_attempts)
                {
                    m_logger.log_debug("[st::engine] waiting to resolve uncontrolled concurrency.");

                    // Release the engine lock and wait for a bit to give chance to any uncontrolled
                    // concurrency to resolve before acquiring the lock again.
                    lock.unlock();

                    // Spin the CPU just for a bit to avoid slowing down the test iteration.
                    auto start = std::chrono::steady_clock::now();
                    size_t interval = m_settings.partially_controlled_concurrency_resolution_interval();
                    while(true)
                    {
                        auto elapsed = (size_t) std::chrono::duration_cast<std::chrono::microseconds>(
                            std::chrono::steady_clock::now() - start).count();
                        if (elapsed > interval * TICKS_PER_MICROSECOND)
                        {
                            break;
                        }
                    }

                    lock.lock();
                    continue;
                }

                break;
            }

            size_t num_enabled_ops = m_operations.size();
            m_report.m_concurrency_degree = std::max<size_t>(m_report.m_concurrency_degree, num_enabled_ops);
            m_report.m_synchronization_degree = std::max<size_t>(m_report.m_synchronization_degree, m_resource_map.size());
            return num_enabled_ops > 0;
        }

        // Creates a new controlled resource with the specified id.
        void create_resource(size_t resource_id)
        {
            if (m_resource_map.find(resource_id) != m_resource_map.end())
            {
                m_logger.log_error("[st::error] unable to create resource '", resource_id,
                    "' from thread '", std::this_thread::get_id(), "' as it already exists.");
                throw Exceptions::ResourceAlreadyExistsError(resource_id);
            }

            m_logger.log_exhaustive("[st::engine] created resource '", resource_id,
                "' from thread '", std::this_thread::get_id(), "'.");
            m_resource_map.insert(std::pair<size_t, std::tuple<std::map<size_t, size_t>, std::set<size_t>>>(
                resource_id, std::make_tuple(std::map<size_t, size_t>(), std::set<size_t>())));
        }

        // Acquires the resource with the specified id.
        void acquire_resource(size_t resource_id, Runtime::Operation* const op)
        {
            auto it = m_resource_map.find(resource_id);
            if (it == m_resource_map.end())
            {
                m_logger.log_error("[st::error] unable to acquire resource '", resource_id,
                    "' from thread '", std::this_thread::get_id(), "' as it does not exist.");
                throw Exceptions::ResourceNotFoundError(resource_id);
            }

            std::map<size_t, size_t>& owner_ops = std::get<0>(it->second);
            m_logger.log_info("[st::engine] acquired resource '", resource_id, "' with '",
                owner_ops.size(), "' owners from thread '", std::this_thread::get_id(), "'.");

            auto op_it = owner_ops.find(op->id);
            if (op_it != owner_ops.end())
            {
                // Increment the number of times the same owner has acquired the resource,
                // which is important to keep track of for resources that can be acquired
                // multiple times by the same owner, for example reentrant locks.
                op_it->second++;
            }
            else
            {
                owner_ops.insert(std::pair<size_t, size_t>(op->id, 1));
            }
        }

        // Waits the resource with the specified id to become available and schedules the next operation.
        void wait_resource(size_t resource_id, Runtime::Operation* const current_op, std::unique_lock<std::mutex>& lock)
        {
            auto it = m_resource_map.find(resource_id);
            if (it == m_resource_map.end())
            {
                m_logger.log_error("[st::error] unable to wait resource '", resource_id,
                    "' from thread '", std::this_thread::get_id(), "' as it does not exist.");
                throw Exceptions::ResourceNotFoundError(resource_id);
            }

            std::map<size_t, size_t>& owner_ops = std::get<0>(it->second);
            std::set<size_t>& blocked_op_ids = std::get<1>(it->second);
            m_logger.log_info("[st::engine] waiting for resource '", resource_id, "' with '",
                owner_ops.size(), "' owners from thread '", std::this_thread::get_id(), "'.");

            current_op->m_status = Runtime::OperationStatus::BlockedOnResource;
            current_op->m_dependent_resource_id = resource_id;
            m_operations.disable(current_op->id);
            blocked_op_ids.insert(current_op->id);
            schedule_next_operation(current_op, lock);
        }

        // Tries to release the resource with the specified id from the currently executing operation.
        // Returns true if the resource has no more owners and is released, else false.
        bool try_release_resource(size_t resource_id, Runtime::Operation* const op)
        {
            auto it = m_resource_map.find(resource_id);
            if (it == m_resource_map.end())
            {
                m_logger.log_error("[st::error] unable to release resource '", resource_id,
                    "' from thread '", std::this_thread::get_id(), "' as it does not exist.");
                throw Exceptions::ResourceNotFoundError(resource_id);
            }

            std::map<size_t, size_t>& owner_ops = std::get<0>(it->second);
            std::set<size_t>& blocked_op_ids = std::get<1>(it->second);

            auto op_it = owner_ops.find(op->id);
            if (op_it == owner_ops.end())
            {
                m_logger.log_error("[st::error] unable to release resource '", resource_id,
                    "' from operation '", op->id, "' as it is not an owner.");
                throw std::runtime_error("not an owner of resource");
            }

            // Check how many times this operation has acquired the resource. If it is one time,
            // the resource has not been reacquired by the same owner, so can be released.
            bool is_released = false;
            if (op_it->second == 1)
            {
                m_logger.log_info("[st::engine] released resource '", resource_id, "' with '",
                    owner_ops.size(), "' owners from thread '", std::this_thread::get_id(), "'.");

                // Remove the operation from the owner set and check if there are no more owners.
                // If that is the case, then unblock all corresponding blocked operations.
                owner_ops.erase(op->id);
                if (owner_ops.empty())
                {
                    for (auto& blocked_op_id : blocked_op_ids)
                    {
                        auto blocked_op = get_operation(blocked_op_id);
                        blocked_op->m_status = Runtime::OperationStatus::Enabled;
                        blocked_op->m_dependent_resource_id = std::nullopt;
                        m_operations.enable(blocked_op->id);
                    }

                    blocked_op_ids.clear();
                    is_released = true;
                }
            }
            else
            {
                m_logger.log_info("[st::engine] releasing resource '", resource_id, "' with '",
                    owner_ops.size(), "' owners that has been acquired '", op_it->second,
                    "' times from thread '", std::this_thread::get_id(), "'.");

                // Decrement the number of times the same owner has acquired the resource.
                op_it->second--;
            }

            return is_released;
        }

        // Returns the operation with the specified id.
        Runtime::Operation* get_operation(size_t op_id) const noexcept
        {
            auto it = m_operation_map.find(op_id);
            if (it != m_operation_map.end())
            {
                return it->second.get();
            }
            else
            {
                return nullptr;
            }
        }

        // Returns the currently executing operation, if the current thread is controlled, else nullptr.
        Runtime::Operation* get_executing_operation()
        {
            auto op_id = get_executing_operation_id();
            if (op_id.has_value())
            {
                auto it = m_operation_map.find(op_id.value());
                if (it != m_operation_map.end())
                {
                    auto op = it->second.get();
                    if (op->iteration == m_iteration_count)
                    {
                        // Only return the operation if it was created in the current test iteration.
                        return op;
                    }
                }
            }

            // No operation is currently executing, which means this is an uncontrolled thread.
            if (m_status == Status::Attached)
            {
                // Log the thread id of the uncontrolled thread.
                auto tid = std::this_thread::get_id();
                if (m_uncontrolled_thread_ids.find(tid) == m_uncontrolled_thread_ids.end())
                {
                    m_logger.log_warning("[st::warning] detected new uncontrolled thread '", tid, "'.");
                    m_uncontrolled_thread_ids.insert(tid);
                }
                else
                {
                    m_logger.log_exhaustive("[st::engine] detected uncontrolled thread '", tid, "'.");
                }

                if (!m_settings.is_partially_controlled_concurrency_allowed())
                {
                    throw Exceptions::UncontrolledInvocationError();
                }
            }

            return nullptr;
        }

        // Returns the currently executing operation, if the current thread is controlled and the
        // specified condition holds, else nullptr.
        Runtime::Operation* get_executing_operation_if(bool condition)
        {
            return condition ? get_executing_operation() : nullptr;
        }

        // Returns the id of the currently executing controlled operation.
        std::optional<size_t> get_executing_operation_id() const noexcept
        {
            return Runtime::get_thread_local_executing_operation_id();
        }

        // Returns the next operation id.
        size_t get_next_operation_id() noexcept
        {
            return m_op_id_count++;
        }

        // Returns the next resource id.
        size_t get_next_resource_id() noexcept
        {
            return m_resource_id_count++;
        }

        // Returns a hash representing the current program state.
        size_t get_current_program_state_hash() const
        {
            std::vector<size_t> hashes;
            for (auto& fn : m_state_hashing_functions)
            {
                hashes.push_back(fn());
            }

            size_t total_hash = 0;
            std::sort(hashes.begin(), hashes.end());
            for (auto& h : hashes)
            {
                total_hash ^= (h << 1);
            }

            return total_hash;
        }

        // Returns true if the exploration has deadlocked, else false.
        bool is_deadlocked()
        {
            // Check if all remaining operations are blocked.
            if (m_operations.size(false) > 0)
            {
                m_logger.log_error("[st::error] deadlock detected.");

                size_t enabled_index = m_operations.size();
                size_t total_size = enabled_index + m_operations.size(false);
                for (size_t index = enabled_index; index < total_size; ++index)
                {
                    std::ostringstream reason;
                    auto op = m_operations[index];
                    if (op->m_status == Runtime::OperationStatus::BlockedOnResource &&
                        op->m_dependent_resource_id.has_value())
                    {
                        // Try to print detailed debug information about the deadlock.
                        size_t resource_id = op->m_dependent_resource_id.value();
                        reason << " on resource '" << resource_id << "'";

                        auto it = m_resource_map.find(resource_id);
                        if (it != m_resource_map.end())
                        {
                            // Identify owners of the resource that blocks the operation.
                            std::map<size_t, size_t>& owner_ops = std::get<0>(it->second);
                            if (owner_ops.size() > 0)
                            {
                                int owner_idx = 0;
                                reason << " owned by operation" << (owner_ops.size() > 1 ? "s" : "");
                                for (auto& owner_op_info : owner_ops)
                                {
                                    auto owner_op = get_operation(owner_op_info.first);
                                    reason << " '" << owner_op->id << "' (tid '" << owner_op->m_thread_id << "')" <<
                                        (owner_idx++ < owner_ops.size() - 1 ? "," : "");
                                }
                            }
                            else
                            {
                                reason << " with unknown owner";
                            }
                        }
                    }

                    m_logger.log_error("[st::error] operation '", op->id, "' executing on thread '",
                        op->m_thread_id , "' is deadlocked", reason.str(), ".");
                }

                return true;
            }

            return false;
        }

        // Detaches the engine to end the current test iteration.
        void detach(bool error_found, std::unique_lock<std::mutex>& lock)
        {
            if (auto op = get_executing_operation_if(m_status == Status::Attached))
            {
                if (!error_found && op->id == 0)
                {
                    // If this is the root '0' operation, then complete it.
                    complete_operation(op, false, lock);
                }

                m_logger.log_info("[st::engine] detaching the test engine from thread '", std::this_thread::get_id(),
                    "' to terminate iteration ", m_iteration_count, ".");
                m_status = Status::Detaching;

                // Release any disabled operations.
                size_t total_size = m_operations.size() + m_operations.size(false);
                for (size_t index = 0; index < total_size; ++index)
                {
                    auto disabled_op = const_cast<Runtime::Operation*>(m_operations[index]);
                    disabled_op->m_cv.notify_one();
                }

                // TODO: add deadlock detection mechanism.
                // TODO: add liveness detection mechanism.

                // Release the engine lock and wait for all threads to terminate.
                lock.unlock();
                wait_threads(m_threads, true);
                wait_threads(m_detached_threads, false);

                // Take back the lock to avoid any race conditions.
                lock.lock();
                m_status = Status::Detached;

                // Updates the test report with coverage data from the current test iteration.
                m_report.m_bugs_found += error_found ? 1 : 0;
                m_report.m_scheduling_decisions += m_strategy->execution_path().length();
                m_report.m_operations += m_operation_map.size();
                m_report.m_op_creation_sequences = m_op_creation_sequence_ids.size();
                m_report.m_resources += m_resource_map.size();
                m_report.m_uncontrolled_threads += m_uncontrolled_thread_ids.size();
                m_report.m_detached_threads = m_detached_threads.size();
                m_report.m_global_detached_threads = m_global_detached_threads.size();
                m_report.m_last_seed = m_strategy->random_seed();

                // Capture the sequence of nondeterministic choices made during the
                // last test iteration for replaying purposes.
                m_report.m_last_trace = m_strategy->execution_path().to_replay_format();

                // Update the execution path coverage information with the unique execution
                // path based on creation sequence ids.
                auto explored_path = m_strategy->execution_path().to_string();
                m_report.m_explored_paths.insert(explored_path);

                // Capture the runtime of the entire test iteration.
                m_report.m_elapsed_test_time += std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - m_clock).count();

                // Reset the state of the engine for the next iteration.
                m_op_id_count = 0;
                m_pending_operations_count = 0;
                m_threads.clear();
                m_detached_threads.clear();
                m_uncontrolled_thread_ids.clear();
                m_state_hashing_functions.clear();
                m_operations.clear();
                m_operation_map.clear();
                m_resource_map.clear();
            }
        }

        // Waits for the specified threads to complete.
        void wait_threads(std::vector<std::thread>& threads, bool is_controlled)
        {
            if (threads.size() > 0)
            {
                m_logger.log_debug("[st::engine] waiting for '", threads.size(), "' ",
                    is_controlled ? "controlled" : "uncontrolled", " threads to complete.");
                for (auto& thread : threads)
                {
                    if (thread.joinable())
                    {
                        thread.join();
                    }
                }
            }
        }
    };

#ifdef SYSTEST_AS_LIBRARY
    // Initializes the global instance of the systematic test engine with the specified
    // settings. Only one global instance of the engine can be set per process.
    SYSTEST_API void InitTestEngine(Settings settings);

    // Removes the global instance of the systematic testing engine. This allows
    // a new instance to be set as global in the process.
    SYSTEST_API void RemoveTestEngine();

    // Returns a pointer to the global instance of the systematic testing engine.
    SYSTEST_API TestEngine* GetTestEngine();
#else
    static TestEngine* g_pEngine = nullptr;

    void InitTestEngine(Settings settings)
    {
        if (g_pEngine)
        {
            // We only allow one global engine to be set at the same time per process.
            throw Exceptions::TestEngineAlreadyInitializedError();
        }

        g_pEngine = new TestEngine(settings);
    }

    void RemoveTestEngine()
    {
        delete g_pEngine;
        g_pEngine = nullptr;
    }

    TestEngine* GetTestEngine()
    {
        return g_pEngine;
    }
#endif

    // Provides the capability to explicitly declare points in the execution where interleavings
    // between controlled operations should be explored during testing.
    class SchedulingPoint
    {
    public:
        // Explores a possible interleaving with another controlled operation.
        static void interleave()
        {
            if (auto engine = GetTestEngine())
            {
                engine->schedule_next_operation();
            }
        }
    };
} // namespace SystematicTesting

#endif // SYSTEMATIC_TESTING_H
