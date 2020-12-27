-module(ddb_util_SUITE).

-include_lib("eunit/include/eunit.hrl").

ddb_util_SUITE_test_() ->
    {
        setup,
        fun setup/0,
        fun teardown/1,
        [
            fun test_load_credentials/0
        ]
    }.

setup() ->
    application:ensure_all_started(econfig).
    
teardown(_) ->
    ok.

test_load_credentials() ->
    % ?debugMsg("load_credentials_test"),
    {ok, AccessKey, Secret, Region} = ddb_util:load_credentitals(),
    ?assertNotEqual(AccessKey, ""),
    ?assertNotEqual(Secret, ""),
    ?assertNotEqual(Region, "").
