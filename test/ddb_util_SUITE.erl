-module(ddb_util_SUITE).

-include_lib("eunit/include/eunit.hrl").

ddb_util_SUITE_test_() ->
    {
        setup,
        fun setup/0,
        fun teardown/1,
        [
        ]
    }.

setup() ->
    application:ensure_all_started(econfig).
    
teardown(_) ->
    ok.
