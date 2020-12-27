-module(ddb_SUITE).

-include_lib("eunit/include/eunit.hrl").

ddb_SUITE_test_() ->
    {
        setup,
        fun setup/0,
        fun teardown/1,
        [
            fun test_list_table/0,
            fun test_crud_table/0
        ]
    }.

setup() ->
    application:ensure_all_started(econfig),
    application:start(ibrowse),

    {ok, Key, Secret, Region} = ddb_util:load_credentitals(),
    ?assertNotEqual(Key, ""),
    ?assertNotEqual(Secret, ""),
    ?assertNotEqual(Region, ""),
    % ?debugFmt("Key=~p, Secret=~p, Region=~p", [Key, Secret, Region]),
    ok = ddb_iam:credentials(Key, Secret),
    {'ok', _, _, Token} = ddb_iam:token(129600),
    % ?debugFmt("Token=~p", [Token]),
    ddb:credentials(Key, Secret, Token, Region, "http://localhost:8000/").

teardown(_) ->
    ok.

test_list_table() ->
    ddb:remove_table(<<"test_table">>),
    {ok, Tables} = ddb:tables(),
    false = lists:member(<<"test_table">>, Tables).

test_crud_table() ->
    {ok, Result1} = ddb:create_table(<<"test_table">>, [ddb:key_type(<<"hashkey">>, <<"HASH">>)], [ddb:attr_type(<<"hashkey">>, 'string')], 10, 10),
    Arn1 = proplists:get_value(<<"TableArn">>, proplists:get_value(<<"TableDescription">>, Result1)),
    
    {ok, Result2} = ddb:describe_table(<<"test_table">>),
    Arn2 = proplists:get_value(<<"TableArn">>, proplists:get_value(<<"Table">>, Result2)),
    
    {ok, Result3} = ddb:remove_table(<<"test_table">>),
    Arn3 = proplists:get_value(<<"TableArn">>, proplists:get_value(<<"TableDescription">>, Result3)),
    
    ?assertEqual(Arn1, Arn2),
    ?assertEqual(Arn1, Arn3).
