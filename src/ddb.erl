%%% Copyright (C) 2012 Issuu ApS. All rights reserved.
%%%
%%% Redistribution and use in source and binary forms, with or without
%%% modification, are permitted provided that the following conditions
%%% are met:
%%% 1. Redistributions of source code must retain the above copyright
%%%    notice, this list of conditions and the following disclaimer.
%%% 2. Redistributions in binary form must reproduce the above copyright
%%%    notice, this list of conditions and the following disclaimer in the
%%%    documentation and/or other materials provided with the distribution.
%%%
%%% THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
%%% ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
%%% IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
%%% ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
%%% FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
%%% DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
%%% OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
%%% HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
%%% LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
%%% OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
%%% SUCH DAMAGE.

-module(ddb).

-export([credentials/3, credentials/4, load_credentials/0,
         tables/0,
         key_type/2, key_type/4,
         key_value/2, key_value/4,
         create_table/4, describe_table/1, remove_table/1,
         get/2, get/3, put/2, update/3, update/4,
         delete/2, delete/3,
         cond_put/3,
         cond_update/4, cond_update/5,
         cond_delete/3, cond_delete/4,
         now/0, find/3, find/4,
         q/3, q/4,
         scan/2, scan/3,
         get_ddb_endpoint/0,
         range_key_condition/1]).

-define(DDB_DEFAULT_ENDPOINT, "http://dynamodb.us-east-1.amazonaws.com/").
-define(MAX_RETRIES, 4).

%%% Endpoint targets

-define(TG_VERSION, "DynamoDB_20120810.").
-define(TG_CREATE_TABLE, ?TG_VERSION ++ "CreateTable").
-define(TG_LIST_TABLES, ?TG_VERSION ++ "ListTables").
-define(TG_DESCRIBE_TABLE, ?TG_VERSION ++ "DescribeTable").
-define(TG_DELETE_TABLE, ?TG_VERSION ++ "DeleteTable").
-define(TG_PUT_ITEM, ?TG_VERSION ++ "PutItem").
-define(TG_GET_ITEM, ?TG_VERSION ++ "GetItem").
-define(TG_UPDATE_ITEM, ?TG_VERSION ++ "UpdateItem").
-define(TG_DELETE_ITEM, ?TG_VERSION ++ "DeleteItem").
-define(TG_QUERY, ?TG_VERSION ++ "Query").
-define(TG_SCAN, ?TG_VERSION ++ "Scan").

-type tablename() :: binary().
-type type() :: 'number' | 'string' | ['number'] | ['string'].
-type condition() :: 'between' | 'equal'. % TBD implement others
-type key_value() :: {binary(), type()}.
-type find_cond() :: {condition(), type(), [_]}.
-type json() :: [_].
-type key_json() :: json().
-type json_reply() :: {'ok', json()} | {'error', json()}.
-type put_attr() :: {binary(), binary(), type()}.
-type update_action() :: 'put' | 'add' | 'delete'.
-type update_attr() :: {binary(), binary(), type(), 'put' | 'add'} | {binary(), 'delete'}.
-type returns() :: 'none' | 'all_old' | 'updated_old' | 'all_new' | 'updated_new'.
-type update_cond() :: {'does_not_exist', binary()} | {'exists', binary(), binary(), type()}.
-type json_parameter() :: {binary(), term()}.
-type json_parameters() :: [json_parameter()].

%%% Set temporary credentials, use ddb_iam:token/1 to fetch from AWS.

-spec credentials(string(), string(), string()) -> 'ok'.

credentials(AccessKeyId, SecretAccessKey, Region) ->
    'ok' = application:set_env('ddb', 'access_key_id', AccessKeyId),
    'ok' = application:set_env('ddb', 'secret_access_key', SecretAccessKey),
    'ok' = application:set_env('ddb', 'region', Region).

-spec credentials(string(), string(), string(), string()) -> 'ok'.

credentials(AccessKeyId, SecretAccessKey, Region, DDBEndpoint) ->
    'ok' = application:set_env('ddb', 'ddb_endpoint', DDBEndpoint),
    credentials(AccessKeyId, SecretAccessKey, Region).

-spec load_credentials() -> {ok, string(), string(), string()}.

load_credentials() ->
    HomePath = os:getenv("HOME","~"),
    AwsCredentialsFile = string:join([HomePath, "/.aws/credentials"], ""),
    ok = econfig:register_config(credentials, [AwsCredentialsFile]),
    ok = econfig:subscribe(credentials),
    AccessKey = econfig:get_value(credentials, "default", "aws_access_key_id", ""),
    Secret = econfig:get_value(credentials, "default", "aws_secret_access_key", ""),
    Region = econfig:get_value(credentials, "default", "region", "us-west-1"),
    {ok, AccessKey, Secret, Region}.


%%% Create a key type, either hash or hash and range.

-spec key_type(binary(), type()) -> json().

key_type(HashKey, HashKeyType)
  when is_binary(HashKey),
       is_atom(HashKeyType) ->
    [{<<"KeySchema">>, [
        [{<<"AttributeName">>, HashKey}, {<<"KeyType">>, <<"HASH">>}]
    ]},    
    {<<"AttributeDefinitions">>, [
        [{<<"AttributeName">>, HashKey}, {<<"AttributeType">>, type(HashKeyType)}]
    ]}].

-spec key_type(binary(), type(), binary(), type()) -> json().

key_type(HashKey, HashKeyType, RangeKey, RangeKeyType)
  when is_binary(HashKey),
       is_atom(HashKeyType),
       is_binary(RangeKey),
       is_atom(RangeKeyType) ->
    [{<<"KeySchema">>, [
        [{<<"AttributeName">>, HashKey}, {<<"KeyType">>, <<"HASH">>}],
        [{<<"AttributeName">>, RangeKey}, {<<"KeyType">>, <<"RANGE">>}]
    ]},    
    {<<"AttributeDefinitions">>, [
        [{<<"AttributeName">>, HashKey}, {<<"AttributeType">>, type(HashKeyType)}],
        [{<<"AttributeName">>, RangeKey}, {<<"AttributeType">>, type(RangeKeyType)}]
    ]}].

%%% Create table. Use key_type/2 or key_type/4 as key.

-spec create_table(tablename(), key_json(), pos_integer(), pos_integer()) -> json_reply().

create_table(Name, Keys, ReadsPerSec, WritesPerSec)
  when is_binary(Name),
       is_list(Keys),
       is_integer(ReadsPerSec),
       is_integer(WritesPerSec) ->
    JSON = [{<<"TableName">>, Name},
            {<<"KeySchema">>, proplists:get_value(<<"KeySchema">>, Keys)},
            {<<"AttributeDefinitions">>, proplists:get_value(<<"AttributeDefinitions">>, Keys)},
            {<<"ProvisionedThroughput">>, [{<<"ReadCapacityUnits">>, ReadsPerSec},
                                           {<<"WriteCapacityUnits">>, WritesPerSec}]}],
    request(?TG_CREATE_TABLE, JSON).

%%% Fetch list of created tabled.

-spec tables() -> {'ok', [tablename()]}.

tables() ->
    {'ok', JSON} = request(?TG_LIST_TABLES, [{}]),
    [{<<"TableNames">>, Tables}] = JSON,
    {'ok', Tables}.

%%% Describe table.

-spec describe_table(tablename()) -> json_reply().

describe_table(Name)
  when is_binary(Name) ->
    JSON = [{<<"TableName">>, Name}],
    request(?TG_DESCRIBE_TABLE, JSON).

%%% Delete table.

-spec remove_table(tablename()) -> json_reply().

remove_table(Name)
  when is_binary(Name) ->
    JSON = [{<<"TableName">>, Name}],
    request(?TG_DELETE_TABLE, JSON).

%%% Put item attributes into table.

-spec put(tablename(), [put_attr()]) -> json_reply().

put(Name, Attributes)
  when is_binary(Name) ->
    JSON = [{<<"TableName">>, Name},
            {<<"Item">>, format_put_attrs(Attributes)}],
    request(?TG_PUT_ITEM, JSON).

%%% Conditionally put item attributes into table

-spec cond_put(tablename(), [put_attr()], update_cond()) -> json_reply().

cond_put(Name, Attributes, Condition)
  when is_binary(Name),
       is_list(Attributes) ->
    JSON = [{<<"TableName">>, Name},
            {<<"Item">>, format_put_attrs(Attributes)}]
        ++ format_update_cond(Condition),
    request(?TG_PUT_ITEM, JSON).

%%% Create a key value, either hash or hash and range.

-spec key_value(binary(), type()) -> json().

key_value(HashKeyValue, HashKeyType)
  when is_binary(HashKeyValue),
       is_atom(HashKeyType) ->
    [{<<"Key">>, [{<<"HashKeyElement">>,
                   [{type(HashKeyType), HashKeyValue}]}]}].

-spec key_value(binary(), type(), binary(), type()) -> json().

key_value(HashKeyValue, HashKeyType, RangeKeyValue, RangeKeyType)
  when is_binary(HashKeyValue),
       is_atom(HashKeyType),
       is_binary(RangeKeyValue),
       is_atom(RangeKeyType) ->
    [{<<"Key">>, [{<<"HashKeyElement">>,
                   [{type(HashKeyType), HashKeyValue}]},
                  {<<"RangeKeyElement">>,
                   [{type(RangeKeyType), RangeKeyValue}]}]}].

%%% Update attributes of an existing item.

-spec update(tablename(), key_json(), [update_attr()]) -> json_reply().

update(Name, Keys, Attributes) ->
    update(Name, Keys, Attributes, 'none').

-spec update(tablename(), key_json(), [update_attr()], returns()) -> json_reply().

update(Name, Keys, Attributes, Returns)
  when is_binary(Name),
       is_list(Keys),
       is_list(Attributes),
       is_atom(Returns) ->
    JSON = [{<<"TableName">>, Name},
            {<<"ReturnValues">>, returns(Returns)}]
        ++ Keys
        ++ [{<<"AttributeUpdates">>, format_update_attrs(Attributes)}],
    request(?TG_UPDATE_ITEM, JSON).

%%% Conditionally update attributes of an existing item.

-spec cond_update(tablename(), key_json(), [update_attr()], update_cond()) -> json_reply().

cond_update(Name, Keys, Attributes, Condition) ->
    cond_update(Name, Keys, Attributes, Condition, 'none').

-spec cond_update(tablename(), key_json(), [update_attr()], update_cond(), returns()) -> json_reply().

cond_update(Name, Keys, Attributes, Condition, Returns)
  when is_binary(Name),
       is_list(Keys),
       is_list(Attributes),
       is_atom(Returns) ->
    JSON = [{<<"TableName">>, Name},
            {<<"ReturnValues">>, returns(Returns)}]
        ++ Keys
        ++ [{<<"AttributeUpdates">>, format_update_attrs(Attributes)}]
        ++ format_update_cond(Condition),
    request(?TG_UPDATE_ITEM, JSON).

%%% Delete existing item.

-spec delete(tablename(), key_json()) -> json_reply().

delete(Name, Keys) ->
    delete(Name, Keys, 'none').

-spec delete(tablename(), key_json(), returns()) -> json_reply().

delete(Name, Keys, Returns)
  when is_binary(Name),
       is_list(Keys),
       is_atom(Returns) ->
    JSON = [{<<"TableName">>, Name},
            {<<"ReturnValues">>, returns(Returns)}]
        ++ Keys,
    request(?TG_DELETE_ITEM, JSON).

%%% Conditionally delete existing item.

-spec cond_delete(tablename(), key_json(), update_cond()) -> json_reply().

cond_delete(Name, Keys, Condition) ->
    cond_delete(Name, Keys, Condition, 'none').

-spec cond_delete(tablename(), key_json(), update_cond(), returns()) -> json_reply().

cond_delete(Name, Keys, Condition, Returns)
  when is_binary(Name),
       is_list(Keys),
       is_atom(Returns) ->
    JSON = [{<<"TableName">>, Name},
            {<<"ReturnValues">>, returns(Returns)}]
        ++ Keys
        ++ format_update_cond(Condition),
    request(?TG_DELETE_ITEM, JSON).

%%% Fetch all item attributes from table.

-spec get(tablename(), key_json()) -> json_reply().

get(Name, Keys)
  when is_binary(Name),
       is_list(Keys) ->
    JSON = [{<<"TableName">>, Name}] ++ Keys,
    request(?TG_GET_ITEM, JSON).

%%% get with additional parameters

-spec get(tablename(), key_json(), json_parameters()) -> json_reply().

get(Name, Keys, Parameters)
  when is_binary(Name),
       is_list(Keys) ->
    JSON = [{<<"TableName">>, Name}]
        ++ Keys
        ++ Parameters,
    request(?TG_GET_ITEM, JSON).

%%% Fetch all item attributes from table using a condition.

-spec find(tablename(), key_value(), find_cond()) -> json_reply().

find(Name, HashKey, RangeKeyCond) ->
    find(Name, HashKey, RangeKeyCond, 'none').

%%% Fetch all item attributes from table using a condition, with pagination.

-spec find(tablename(), key_value(), find_cond(), json() | 'none') -> json_reply().

find(Name, {HashKeyValue, HashKeyType}, RangeKeyCond, StartKey)
  when is_binary(Name),
       is_binary(HashKeyValue),
       is_atom(HashKeyType) ->
    JSON = [{<<"TableName">>, Name},
            {<<"HashKeyValue">>,
             [{type(HashKeyType), HashKeyValue}]},
            range_key_condition(RangeKeyCond)]
        ++ start_key(StartKey),

    request(?TG_QUERY, JSON).

%%% Create a range key condition parameter

-spec range_key_condition(find_cond()) -> json_parameter().
range_key_condition({Condition, RangeKeyType, RangeKeyValues})
  when is_atom(Condition),
       is_atom(RangeKeyType),
       is_list(RangeKeyValues) ->
    {Op, Values} = case Condition of
                       'between' ->
                           [A, B] = RangeKeyValues,
                           {<<"BETWEEN">>, [[{type(RangeKeyType), A}],
                                            [{type(RangeKeyType), B}]]};
                       'equal' ->
                           {<<"EQ">>, [[{type(RangeKeyType), hd(RangeKeyValues)}]]}
                   end,
    {<<"RangeKeyCondition">>, [{<<"AttributeValueList">>, Values},
                               {<<"ComparisonOperator">>, Op}]}.

%%% Query a table

-spec q(tablename(), key_value(), json_parameters()) -> json_reply().

q(Name, HashKey, Parameters) ->
    q(Name, HashKey, Parameters, 'none').

%% Query a table with pagination

-spec q(tablename(), key_value(), json_parameters(), json() | 'none') -> json_reply().

q(Name, {HashKeyValue, HashKeyType}, Parameters, StartKey)
  when is_binary(Name),
       is_binary(HashKeyValue),
       is_atom(HashKeyType),
       is_list(Parameters) ->
    JSON = [{<<"TableName">>, Name},
            {<<"HashKeyValue">>, [{type(HashKeyType), HashKeyValue}]}]
        ++ Parameters
        ++ start_key(StartKey),
    request(?TG_QUERY, JSON).

%%% Scan a table

-spec scan(tablename(), json_parameters()) -> json_reply().

scan(Name, Parameters) ->
    scan(Name, Parameters, 'none').

%% Scan a table with pagination

-spec scan(tablename(), json_parameters(), json() | 'none') -> json_reply().

scan(Name, Parameters, StartKey)
  when is_binary(Name),
       is_list(Parameters) ->
    JSON = [{<<"TableName">>, Name}]
        ++ Parameters
        ++ start_key(StartKey),
    request(?TG_SCAN, JSON).

%%%
%%% Helper functions
%%%

-spec get_ddb_endpoint() -> string().

get_ddb_endpoint() ->
    case application:get_env('ddb', 'ddb_endpoint') of
        {'ok', DDBEndpoint} ->
            DDBEndpoint;
        _ ->
            ?DDB_DEFAULT_ENDPOINT
    end.

-spec start_key(json() | 'none') -> json_parameters().
start_key('none') ->
    [];
start_key(StartKey) ->
    [{<<"ExclusiveStartKey">>, StartKey}].

-spec format_put_attrs([put_attr()]) -> json().

format_put_attrs(Attributes) ->
    lists:map(fun({Name, Value, Type}) ->
                      {Name, [{type(Type), Value}]}
              end, Attributes).

-spec format_update_attrs([update_attr()]) -> json().

format_update_attrs(Attributes) ->
    lists:map(fun({Name, Value, Type, Action}) ->
                      {Name, [{<<"Value">>, [{type(Type), Value}]},
                              {<<"Action">>, update_action(Action)}]};
                 ({Name, 'delete'}) ->
                      {Name, [{<<"Action">>, update_action('delete')}]}
              end, Attributes).

-spec format_update_cond(update_cond()) -> json().

format_update_cond({'does_not_exist', Name}) ->
    [{<<"Expected">>, [{Name, [{<<"Exists">>, <<"false">>}]}]}];

format_update_cond({'exists', Name, Value, Type}) ->
    [{<<"Expected">>, [{Name, [{<<"Value">>, [{type(Type), Value}]}]}]}].

-spec type(type()) -> binary().

type('string') -> <<"S">>;
type('number') -> <<"N">>;
type(['string']) -> <<"SS">>;
type(['number']) -> <<"NN">>.

-spec returns(returns()) -> binary().

returns('none') -> <<"NONE">>;
returns('all_old') -> <<"ALL_OLD">>;
returns('updated_old') -> <<"UPDATED_OLD">>;
returns('all_new') -> <<"ALL_NEW">>;
returns('updated_new') -> <<"UPDATED_NEW">>.

-spec update_action(update_action()) -> binary().

update_action('put') -> <<"PUT">>;
update_action('add') -> <<"ADD">>;
update_action('delete') -> <<"DELETE">>.

-spec request(string(), json()) -> json_reply().

request(Target, JSON) ->
    Now = edatetime:now2ts(),
    Body = jsx:encode(JSON),
    URL = get_ddb_endpoint(),
    Headers = [{<<"Host">>,         config_aws_host()},
               {<<"Content-Type">>, <<"application/x-amz-json-1.0">>},
               {<<"X-Amz-Date">>,   edatetime:iso8601(Now)},
               {<<"X-Amz-Target">>, Target}
              ],
    Signed = [{<<"Authorization">>, authorization(Headers, Body, Now)}
              | Headers],
    Opts = [{'response_format', 'binary'}],
    %io:format("URL=~p Signed=~p, Body=~p, Opts=~p", [URL, Signed, Body, Opts]),
    F = fun() -> ibrowse:send_req(URL, Signed, 'post', Body, Opts) end,
    case ddb_aws:retry(F, ?MAX_RETRIES, fun jsx:decode/1) of
        {'error', 'expired_token'} ->
            {ok, Key, Secret, Token} = ddb_iam:token(129600),
            ddb:credentials(Key, Secret, Token),
            request(Target, JSON);
        Else ->
            Else
    end.


%%
%% AWS4 request signing
%% http://docs.aws.amazon.com/general/latest/gr/signature-version-4.html
%%

authorization(Headers, Body, Now) ->
    CanonicalRequest = canonical(Headers, Body),

    HashedCanonicalRequest = base16:encode(crypto:hash(sha256, CanonicalRequest)),

    StringToSign = string_to_sign(HashedCanonicalRequest, Now),

    iolist_to_binary(
      ["AWS4-HMAC-SHA256 ",
       "Credential=", credential(Now), ", ",
       "SignedHeaders=", string:join([to_lower(K)
                                      || {K, _} <- lists:sort(Headers)],
                                     ";"), ", ",
       "Signature=", signature(StringToSign, Now)]).


config_access_key() ->
    {ok, Access} = application:get_env(ddb, access_key_id),
    Access.

config_secret_key() ->
    {ok, Secret} = application:get_env(ddb, secret_access_key),
    Secret.

config_region() ->
    {ok, Region} = application:get_env(ddb, region),
    Region.

config_aws_host() ->
    Result = uri_string:parse(get_ddb_endpoint()),
    maps:get(host,Result).

credential(Now) ->
    [config_access_key(), "/", format_ymd(Now), "/", config_region(), "/",
     config_aws_host(), "/aws4_request"].

string_to_sign(HashedCanonicalRequest, Now) ->
    ["AWS4-HMAC-SHA256", "\n",
     binary_to_list(edatetime:iso8601_basic(Now)), "\n",
     [format_ymd(Now), "/", config_region(), "/", config_aws_host(),
      "/aws4_request"], "\n", HashedCanonicalRequest].

derived_key(Now) ->
    Secret  = ["AWS4", config_secret_key()],
    Date    = crypto:mac(hmac, sha256, Secret, format_ymd(Now)),
    Region  = crypto:mac(hmac, sha256, Date, config_region()),
    Service = crypto:mac(hmac, sha256, Region, config_aws_host()),
    crypto:mac(hmac, sha256, Service, "aws4_request").

signature(StringToSign, Now) ->
    Key = derived_key(Now),
    base16:encode(crypto:mac(hmac, sha256, Key, StringToSign)).

canonical(Headers, Body) ->
    string:join(
      ["POST",
       "/",
       "",
       [[to_lower(K), ":", V, "\n"] || {K, V} <- lists:sort(Headers)],
       string:join([to_lower(K) || {K, _} <- lists:sort(Headers)],
                   ";"),
       hexdigest(Body)],
      "\n").

%% Formatting helpers
hexdigest(Body) ->
    binary_to_list(base16:encode(crypto:hash(sha256, Body))).

format_ymd(Now) ->
    {Y, M, D} = edatetime:ts2date(Now),
    io_lib:format("~4.10.0B~2.10.0B~2.10.0B", [Y, M, D]).

to_lower(Binary) when is_binary(Binary) ->
    to_lower(binary_to_list(Binary));
to_lower(List) ->
    string:to_lower(List).

now() ->
    edatetime:now2ts().
