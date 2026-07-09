-module(otel_propagator_baggage_SUITE).

-compile(export_all).

-include_lib("stdlib/include/assert.hrl").
-include_lib("common_test/include/ct.hrl").

-include("opentelemetry.hrl").

-define(BAGGAGE_HEADER, <<"baggage">>).
-define(MAX_BAGGAGE_BYTES, 8192).
-define(MAX_BAGGAGE_ENTRIES, 180).

all() ->
    [extract_simple,
     extract_drops_oversized_header,
     extract_caps_entry_count,
     extract_within_caps,
     extract_skips_malformed_pair,
     extract_skips_undecodable_pair,
     extract_preserves_empty_value,
     extract_missing_header,
     extract_ignores_invalid_iolist,
     extract_ignores_undecodable_binary,
     extract_rejects_non_string_value].

init_per_suite(Config) ->
    application:load(opentelemetry_api),
    Config.

end_per_suite(_Config) ->
    ok.

init_per_testcase(_TC, Config) ->
    otel_ctx:clear(),
    Config.

end_per_testcase(_TC, _Config) ->
    otel_ctx:clear(),
    ok.

extract_simple(_Config) ->
    Header = <<"k1=v1,k2=v2">>,
    Ctx = extract(Header),
    Baggage = otel_baggage:get_all(Ctx),
    ?assertEqual(2, maps:size(Baggage)),
    ?assertEqual({<<"v1">>, []}, maps:get(<<"k1">>, Baggage)),
    ?assertEqual({<<"v2">>, []}, maps:get(<<"k2">>, Baggage)),
    ok.

extract_drops_oversized_header(_Config) ->
    Header = build_header(2000),
    ?assert(byte_size(Header) > ?MAX_BAGGAGE_BYTES),
    Ctx = extract(Header),
    ?assertEqual(#{}, otel_baggage:get_all(Ctx)),
    ok.

extract_caps_entry_count(_Config) ->
    %% Build a header that stays under the byte cap but carries more entries
    %% than `?MAX_BAGGAGE_ENTRIES`. Short keys/values keep each pair small
    %% enough that 300 entries are well under 8 KiB.
    Header = build_short_header(300),
    ?assert(byte_size(Header) =< ?MAX_BAGGAGE_BYTES),
    Ctx = extract(Header),
    Baggage = otel_baggage:get_all(Ctx),
    ?assertEqual(?MAX_BAGGAGE_ENTRIES, maps:size(Baggage)),
    ok.

extract_within_caps(_Config) ->
    Header = build_short_header(50),
    Ctx = extract(Header),
    Baggage = otel_baggage:get_all(Ctx),
    ?assertEqual(50, maps:size(Baggage)),
    ok.

extract_skips_malformed_pair(_Config) ->
    Header = <<"k1=v1,malformed,k2=v2">>,
    Ctx = extract(Header),
    Baggage = otel_baggage:get_all(Ctx),
    ?assertEqual(2, maps:size(Baggage)),
    ?assertEqual({<<"v1">>, []}, maps:get(<<"k1">>, Baggage)),
    ?assertEqual({<<"v2">>, []}, maps:get(<<"k2">>, Baggage)),
    ok.

extract_skips_undecodable_pair(_Config) ->
    %% `decode_key/1' and `decode_value/1' throw on invalid percent encoding
    %% (`%ZZ'); such a pair is attacker-controlled content and is skipped like
    %% one with no `=', without aborting extraction or dropping valid entries.
    BadBetweenGood =
        [<<"k1=v1,k=%ZZ,k2=v2">>,      %% bad percent encoding in a value
         <<"k1=v1,%ZZ=v,k2=v2">>,      %% bad percent encoding in a key
         <<"k1=v1,k=v;%ZZ,k2=v2">>],   %% bad percent encoding in metadata
    [begin
         Ctx = extract(Header),
         Baggage = otel_baggage:get_all(Ctx),
         ?assertEqual(2, maps:size(Baggage)),
         ?assertEqual({<<"v1">>, []}, maps:get(<<"k1">>, Baggage)),
         ?assertEqual({<<"v2">>, []}, maps:get(<<"k2">>, Baggage))
     end || Header <- BadBetweenGood],

    %% A header that is nothing but an undecodable pair yields no baggage
    %% rather than crashing.
    [?assertEqual(#{}, otel_baggage:get_all(extract(Header)))
     || Header <- [<<"k=%ZZ">>, <<"%ZZ=v">>, <<"k=v;%ZZ">>]],
    ok.

extract_preserves_empty_value(_Config) ->
    %% An empty value is valid by the W3C grammar (`value = *baggage-octet'),
    %% so `k=' must extract an empty value rather than being dropped, and a
    %% leading `;' (`k=;p') must keep that empty value instead of misparsing
    %% `p' as it -- the old `string:lexemes/2' split dropped empty segments.
    ?assertEqual(#{<<"k">> => {<<>>, []}},
                 otel_baggage:get_all(extract(<<"k=">>))),
    ?assertEqual(#{<<"k">> => {<<>>, [<<"p">>]}},
                 otel_baggage:get_all(extract(<<"k=;p">>))),

    %% an empty value keeps its valid neighbors
    Baggage = otel_baggage:get_all(extract(<<"k1=v1,k=,k2=v2">>)),
    ?assertEqual(3, maps:size(Baggage)),
    ?assertEqual({<<"v1">>, []}, maps:get(<<"k1">>, Baggage)),
    ?assertEqual({<<>>, []}, maps:get(<<"k">>, Baggage)),
    ?assertEqual({<<"v2">>, []}, maps:get(<<"k2">>, Baggage)),

    %% consecutive/trailing `;' carry no empty property
    ?assertEqual({<<"v">>, []},
                 maps:get(<<"k">>, otel_baggage:get_all(extract(<<"k=v;">>)))),
    ?assertEqual({<<"v">>, [<<"p">>]},
                 maps:get(<<"k">>, otel_baggage:get_all(extract(<<"k=v;;p">>)))),
    ok.

extract_missing_header(_Config) ->
    Ctx0 = otel_ctx:new(),
    Ctx1 = otel_propagator_baggage:extract(Ctx0, #{},
                                           fun(C) -> maps:keys(C) end,
                                           fun(K, C) -> maps:get(K, C, undefined) end,
                                           []),
    ?assertEqual(Ctx0, Ctx1),
    ok.

extract_ignores_invalid_iolist(_Config) ->
    %% Lists that aren't valid iolists (non-byte integers, improper lists)
    %% are attacker-controlled content; treat them as missing rather than
    %% crashing in `iolist_size/1'.
    [begin
         Ctx = extract(Header),
         ?assertEqual(#{}, otel_baggage:get_all(Ctx))
     end || Header <- [[300], [1 | 2]]],
    ok.

extract_ignores_undecodable_binary(_Config) ->
    %% A binary whose bytes aren't valid UTF-8 makes `string:lexemes/2'
    %% raise (e.g., `badarg'); treat it as missing rather than crashing in
    %% `decode_pairs/3'.
    Ctx = extract(<<255>>),
    ?assertEqual(#{}, otel_baggage:get_all(Ctx)),
    ok.

extract_rejects_non_string_value(_Config) ->
    %% A carrier value that isn't a binary or list violates the TextMap
    %% carrier contract; reject it loudly instead of silently ignoring it.
    [?assertError({invalid_baggage_header, _}, extract(Value))
     || Value <- [42, foo, #{}]],
    ok.

%% helpers

extract(Header) ->
    Carrier = #{?BAGGAGE_HEADER => Header},
    Ctx = otel_ctx:new(),
    otel_propagator_baggage:extract(Ctx, Carrier,
                                    fun(C) -> maps:keys(C) end,
                                    fun(K, C) -> maps:get(K, C, undefined) end,
                                    []).

build_header(N) ->
    Pairs = [io_lib:format("k~B=v~B", [I, I]) || I <- lists:seq(1, N)],
    iolist_to_binary(lists:join(<<",">>, Pairs)).

build_short_header(N) ->
    Pairs = [["k", integer_to_list(I), "=v"] || I <- lists:seq(1, N)],
    iolist_to_binary(lists:join(<<",">>, Pairs)).
