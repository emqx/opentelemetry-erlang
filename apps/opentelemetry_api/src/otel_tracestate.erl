%%%------------------------------------------------------------------------
%% Copyright 2019, OpenTelemetry Authors
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%
%% @doc tracestate provides additional vendor-specific trace identification
%% information across different distributed tracing systems. It represents an
%% immutable list consisting of key/value pairs, each pair is referred to as a
%% list-member.
%%
%% Keys and values are strings of up to 256 printable US-ASCII characters,
%% conforming to the W3C spec https://www.w3.org/TR/trace-context/#tracestate-field
%%
%% @end
%%%-----------------------------------------------------------------------
-module(otel_tracestate).

-export([new/0,
         new/1,
         get/2,
         add/3,
         remove/2,
         update/3,
         decode_header/1,
         encode_header/1
        ]).

-type members() :: [{unicode:latin1_chardata(), unicode:latin1_chardata()}].

-record(tracestate, {members :: members()}).
-type t() :: #tracestate{}.

-export_type([t/0,
              members/0]).

%% See https://www.w3.org/TR/trace-context/#tracestate-header
%% for the limits and string requirements that make up the regexes
-define(MAX_MEMBERS, 32).
%% emqx fork: was
%% re:compile("^(([a-z][_0-9a-z\-\*\/]{0,255})|([a-z0-9][_0-9a-z-*/]{0,240}@[a-z][_0-9a-z-*/]{0,13}))$")
%% re:compile("^([ -+--<>-~]{0,255}[!-+--<>-~])$")
%% upstream at https://github.com/open-telemetry/opentelemetry-erlang/blob/4cc1e9ba6a8004db2f4c0be87b8012da00c4db0c/apps/opentelemetry_api/src/otel_tracestate.erl#L121
%% {ok, KeyMP} = re:compile("^[a-z0-9][a-z0-9_*/@-]{0,255}$"),
%% {ok, ValueMP} = re:compile("^([ -+--<>-~]{0,255}[!-+--<>-~])$"),
-define(KEY_MP, {?MODULE, key_mp}).
-define(VALUE_MP, {?MODULE, value_mp}).

-spec new() -> t().
new() ->
    #tracestate{members=[]}.

-spec new([{unicode:latin1_chardata(), unicode:latin1_chardata()}]) -> t().
new(List) ->
    Members = [Element || {Key, Value}=Element <- List, is_valid(Key, Value)],
    #tracestate{members=Members}.

-spec add(unicode:latin1_chardata(), unicode:latin1_chardata(), t()) -> t().
add(Key, Value, Tracestate=#tracestate{members=TracestateList}) ->
    case is_valid(Key, Value) of
        true ->
            Tracestate#tracestate{members=[{Key, Value} | TracestateList]};
        false ->
            Tracestate
    end.

-spec get(unicode:latin1_chardata(), t()) -> unicode:latin1_chardata().
get(Key, #tracestate{members=TracestateList}) ->
    case lists:keyfind(Key, 1, TracestateList) of
        false ->
            "";
        {_, Value} ->
            Value
    end.

-spec remove(unicode:latin1_chardata(), t()) -> t().
remove(Key, Tracestate=#tracestate{members=TracestateList}) ->
    Tracestate#tracestate{members=lists:keydelete(Key, 1, TracestateList)}.

-spec update(unicode:latin1_chardata(), unicode:latin1_chardata(), t()) -> t().
update(Key, Value, Tracestate=#tracestate{members=TracestateList}) ->
    case is_valid(Key, Value) of
        true ->
            Tracestate#tracestate{members=[{Key, Value} | lists:keydelete(Key, 1, TracestateList)]};
        false ->
            Tracestate
    end.

-spec decode_header(string() | undefined) -> t().
decode_header(undefined) ->
    new();
decode_header(Value) ->
    #tracestate{members=parse_pairs(string:lexemes(Value, [$,]))}.

-spec encode_header(t()) -> unicode:latin1_binary().
encode_header(#tracestate{members=Entries=[_|_]}) ->
    StateHeaderValue = lists:join($,, [[Key, $=, Value] || {Key, Value} <- Entries]),
    otel_utils:assert_to_binary(StateHeaderValue);
encode_header(_) ->
    <<>>.

%%

is_valid(Key, Value) ->
    try
        re:run(Key, key_mp(), [{capture, none}]) =:= match
            andalso re:run(Value, value_mp(), [{capture, none}]) =:= match
    catch
        _:_ ->
            false
    end.

key_mp() ->
    case persistent_term:get(?KEY_MP, undefined) of
        undefined ->
            {ok, Pat} = re:compile("^[a-z0-9][a-z0-9_*/@-]{0,255}$"),
            persistent_term:put(?KEY_MP, Pat),
            Pat;
        Pat ->
            Pat
    end.

value_mp() ->
    case persistent_term:get(?VALUE_MP, undefined) of
        undefined ->
            {ok, Pat} = re:compile("^([ -+--<>-~]{0,255}[!-+--<>-~])$"),
            persistent_term:put(?VALUE_MP, Pat),
            Pat;
        Pat ->
            Pat
    end.

parse_pairs(Pairs) when length(Pairs) =< ?MAX_MEMBERS ->
    parse_pairs(Pairs, []);
parse_pairs(_) ->
    [].

parse_pairs([], Acc) ->
    Acc;
parse_pairs([Pair | Rest], Acc) ->
    case split(string:trim(Pair)) of
        {K, V} ->
            case re:run(K, key_mp()) =/= nomatch
                andalso re:run(V, value_mp()) =/= nomatch
            of
                false ->
                    [];
                true ->
                    %% replace existing key value or append to the end of the list
                    parse_pairs(Rest, lists:keystore(K, 1, Acc, {K, V}))
            end;
        undefined ->
            []
    end.

split(Pair) ->
    case string:split(Pair, "=", all) of
        [Key, Value] when Value =/= [] andalso Value =/= <<>> ->
            {otel_utils:assert_to_binary(Key),
             otel_utils:assert_to_binary(Value)};
        _ ->
            undefined
    end.
