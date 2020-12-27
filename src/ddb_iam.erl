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

-module(ddb_iam).

-export([credentials/2, token/1]).

-include_lib("ibrowse/include/ibrowse.hrl").
-include_lib("xmerl/include/xmerl.hrl").

-define(IAM_ENDPOINT, "https://sts.amazonaws.com/").
-define(IAM_AWS_VERSION, "2011-06-15").
-define(IAM_HEADER_AUTHORIZATION, "Authorization").
-define(IAM_HEADER_AWS_VERSION, "AWS-Version").
-define(IAM_HEADER_CONTENT_MD5, "Content-MD5").
-define(IAM_HEADER_CONTENT_TYPE, "Content-Type").
-define(IAM_HEADER_DATE, "Date").
-define(IAM_MAX_RETRIES, 3).
-define(IAM_STATUS_SUCCESS_OK, "200").
-define(IAM_STATUS_SUCCESS_NO_CONTENT, "204").

-define(MIME_TYPE, "application/x-www-form-urlencoded").

-spec credentials(string(), string()) -> 'ok'.

credentials(AccessKeyId, SecretAccessKey) ->
    'ok' = application:set_env('iam', 'accesskeyid', AccessKeyId),
    'ok' = application:set_env('iam', 'secretaccesskey', SecretAccessKey).

-spec credentials() -> {'ok', string(), string()}.

credentials() ->
    {'ok', AccessKeyId} = application:get_env('iam', 'accesskeyid'),
    {'ok', SecretAccessKey} = application:get_env('iam', 'secretaccesskey'),
    {'ok', AccessKeyId, SecretAccessKey}.

-spec token(pos_integer()) -> {'ok', string(), string(), string()} |
			      {'error', 'maximum_retries_reached'} |
                              {'error', string(), string()}.

token(Duration) 
  when is_integer(Duration) ->
    case request("GetSessionToken", ?IAM_ENDPOINT, Duration) of
        {'ok', XML} ->
            RElem = ddb_xml:get_child(XML, 'GetSessionTokenResult'),
            CElem = ddb_xml:get_child(RElem, 'Credentials'),
            Token = ddb_xml:get_child_text(CElem, 'SessionToken'),
            Key = ddb_xml:get_child_text(CElem, 'AccessKeyId'),
            Secret = ddb_xml:get_child_text(CElem, 'SecretAccessKey'),
            {'ok', Key, Secret, Token};
        Error = {'error', 'maximum_retries_reached'} -> 
            Error;
        {'error', XML} ->
            Error = ddb_xml:get_child(XML, 'Error'),
            Code = ddb_xml:get_child_text(Error, 'Code'),
            Message = ddb_xml:get_child_text(Error, 'Message'),
            {'error', Code, Message}
    end.

-spec request(string(), string(), non_neg_integer()) -> {'ok', #xmlElement{}} | 
							{'error', 'maximum_retries_reached'} |
                                                        {'error', #xmlElement{}}.

request(Action, Endpoint, Duration) ->
    {'ok', AccessKeyId, SecretAccessKey} = credentials(),
    Args = [{"AWSAccessKeyId", AccessKeyId},
            {"Action", Action},
            {"DurationSeconds", Duration},
            {"SignatureMethod", "HmacSHA1"},
            {"SignatureVersion", "2"},
            {"Timestamp", ddb_aws:timestamp()},
            {"Version", ?IAM_AWS_VERSION}],
    CanonicalString = urlencode(lists:sort(Args)),
    #url{host=Host, path=Path} = ibrowse_lib:parse_url(Endpoint),
    S = ["POST", $\n, Host, $\n, Path, $\n, CanonicalString],
    Signature = base64:encode_to_string(crypto:mac(hmac, sha, SecretAccessKey, S)),
    Args1 = [{"Signature", Signature}|Args],
    Body = iolist_to_binary(urlencode(lists:sort(Args1))), 
    F = fun() -> ibrowse:send_req(Endpoint, [{'Content-type', ?MIME_TYPE}], 'post', Body, []) end,
    H = fun ddb_xml:parse/1,
    ddb_aws:retry(F, ?IAM_MAX_RETRIES, H).


% urlencode utils
-define(PERCENT, 37).  % $\%
-define(FULLSTOP, 46). % $\.
-define(QS_SAFE(C), ((C >= $a andalso C =< $z) orelse
                     (C >= $A andalso C =< $Z) orelse
                     (C >= $0 andalso C =< $9) orelse
                     (C =:= ?FULLSTOP orelse C =:= $- orelse C =:= $~ orelse
                      C =:= $_))).

hexdigit(C) when C < 10 -> $0 + C;
hexdigit(C) when C < 16 -> $A + (C - 10).

quote_plus([], Acc) ->
    lists:reverse(Acc);
quote_plus([C | Rest], Acc) when ?QS_SAFE(C) ->
    quote_plus(Rest, [C | Acc]);
quote_plus([$\s | Rest], Acc) ->
    quote_plus(Rest, [$+ | Acc]);
quote_plus([C | Rest], Acc) ->
    <<Hi:4, Lo:4>> = <<C>>,
    quote_plus(Rest, [hexdigit(Lo), hexdigit(Hi), ?PERCENT | Acc]).

%% @spec quote_plus(atom() | integer() | float() | string() | binary()) -> string()
%% @doc URL safe encoding of the given term.
quote_plus(Atom) when is_atom(Atom) ->
    quote_plus(atom_to_list(Atom));
quote_plus(Int) when is_integer(Int) ->
    quote_plus(integer_to_list(Int));
quote_plus(Binary) when is_binary(Binary) ->
    quote_plus(binary_to_list(Binary));
quote_plus(Float) when is_float(Float) ->
    quote_plus(mochinum:digits(Float));
quote_plus(String) ->
    quote_plus(String, []).

urlencode(Props) ->
    Pairs = lists:foldr(
              fun ({K, V}, Acc) ->
                      [quote_plus(K) ++ "=" ++ quote_plus(V) | Acc]
              end, [], Props),
    string:join(Pairs, "&").
