-module(opentelemetry_exporter_SUITE).

-compile(export_all).
-compile(nowarn_export_all).

-include_lib("stdlib/include/assert.hrl").
-include_lib("common_test/include/ct.hrl").
-include_lib("opentelemetry_api/include/opentelemetry.hrl").
-include_lib("opentelemetry_api/include/otel_tracer.hrl").
-include_lib("opentelemetry/include/otel_span.hrl").
-include_lib("opentelemetry_experimental/include/otel_metrics.hrl").

all() ->
    [{group, functional}, {group, http_protobuf}, {group, http_protobuf_gzip},
     {group, grpc}, {group, grpc_gzip}].

groups() ->
    [{functional, [], [configuration, span_round_trip, ets_instrumentation_info]},
     {grpc, [], [verify_export, verify_metrics_export]},
     {grpc_gzip, [], [verify_export]},
     {http_protobuf, [], [verify_export]},
     {http_protobuf_gzip, [], [verify_export]}].

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.

init_per_group(Group, Config) when Group =:= grpc ;
                                   Group =:= http_protobuf ->
    application:ensure_all_started(opentelemetry_exporter),
    application:ensure_all_started(opentelemetry),
    [{protocol, Group}| Config];
init_per_group(http_protobuf_gzip, Config) ->
    application:ensure_all_started(opentelemetry_exporter),
    application:ensure_all_started(opentelemetry),
    [{protocol, http_protobuf}, {compression, gzip} | Config];
init_per_group(grpc_gzip, Config) ->
    application:ensure_all_started(opentelemetry_exporter),
    application:ensure_all_started(opentelemetry),
    [{protocol, grpc}, {compression, gzip} | Config];
init_per_group(_, _) ->
    application:load(opentelemetry_exporter),
    application:ensure_all_started(opentelemetry),
    ok.

end_per_group(Group, _Config) when Group =:= grpc ;
                                   Group =:= http_protobuf ->
    application:stop(opentelemetry),
    application:stop(opentelemetry_exporter),
    %% stop grpc clients pools, that are started under grpc sup
    application:stop(grpc),
    ok;
end_per_group(_, _) ->
    application:stop(opentelemetry),
    application:unload(opentelemetry_exporter),
    ok.

verify_metrics_export(Config) ->
    os:putenv("OTEL_RESOURCE_ATTRIBUTES", "service.name=my-test-service,service.version=98da75ea6d38724743bf42b45565049238d86b3f,schema_url=https://opentelemetry.io/schemas/1.8.0"),
    Protocol = ?config(protocol, Config),
    Compression = ?config(compression, Config),

    Port = case Protocol of
               grpc ->
                   4317;
               http_protobuf ->
                   4318
           end,

    {ok, State} = opentelemetry_exporter:init(metrics,
                                              test_metrics_exporter,
                                              #{protocol => Protocol,
                                                compression => Compression,
                                                endpoint => #{scheme => "http", host => "localhost",
                                                              port => Port, path => []}}),
    Metrics = [#metric{scope=#instrumentation_scope{name = <<"scope-1">>,
                                                    version = <<"version-1">>,
                                                    schema_url = <<"https://example.com/schemas/1.8.0">>},
                       name = <<"sum name">>,
                       description = <<"some sum description">>,
                       unit = kb,
                       data = #sum{aggregation_temporality = temporality_cumulative,
                                   is_monotonic=true,
                                   datapoints=[#datapoint{
                                                  attributes=otel_attributes:new(#{<<"key-1">> => <<"value-1">>},
                                                                                 128, 128),
                                                  start_time=opentelemetry:timestamp(),
                                                  time=opentelemetry:timestamp(),
                                                  value=5,
                                                  exemplars=[],
                                                  flags=0
                                                 },
                                               #datapoint{
                                                  attributes=otel_attributes:new(#{<<"key-2">> => <<"value-2">>},
                                                                                 128, 128),
                                                  start_time=opentelemetry:timestamp(),
                                                  time=opentelemetry:timestamp(),
                                                  value=8,
                                                  exemplars=[],
                                                  flags=0
                                                 }]}},
               #metric{scope=#instrumentation_scope{name = <<"scope-1">>,
                                                    version = <<"version-1">>,
                                                    schema_url = <<"https://example.com/schemas/1.8.0">>},
                       name = <<"gauge name">>,
                       description = <<"some gauge description">>,
                       unit = kb,
                       data = #gauge{datapoints=[#datapoint{
                                                    attributes=otel_attributes:new(#{<<"key-1">> => <<"value-1">>},
                                                                                   128, 128),
                                                    start_time=opentelemetry:timestamp(),
                                                    time=opentelemetry:timestamp(),
                                                    value=8,
                                                    exemplars=[],
                                                    flags=0
                                                   },
                                                 #datapoint{
                                                    attributes=otel_attributes:new(#{<<"key-2">> => <<"value-2">>},
                                                                                   128, 128),
                                                    start_time=opentelemetry:timestamp(),
                                                    time=opentelemetry:timestamp(),
                                                    value=9,
                                                    exemplars=[],
                                                    flags=0
                                                   }]}},
               #metric{scope=#instrumentation_scope{name = <<"scope-1">>,
                                                    version = <<"version-1">>,
                                                    schema_url = <<"https://example.com/schemas/1.8.0">>},
                       name = <<"histogram name">>,
                       description = <<"some histogram description">>,
                       unit = kb,
                       data = #histogram{aggregation_temporality = temporality_cumulative,
                                         datapoints=[#histogram_datapoint{
                                                        attributes=otel_attributes:new(#{<<"key-1">> => <<"value-1">>},
                                                                                       128, 128),
                                                        start_time=opentelemetry:timestamp(),
                                                        time=opentelemetry:timestamp(),
                                                        count = 3,
                                                        sum = 9,
                                                        bucket_counts = [1,1,1],
                                                        explicit_bounds = [0,3,5],
                                                        exemplars = [],
                                                        flags = 0,
                                                        min = 1,
                                                        max = 5
                                                       },
                                                     #histogram_datapoint{
                                                        attributes=otel_attributes:new(#{<<"key-2">> => <<"value-2">>},
                                                                                       128, 128),
                                                        start_time=opentelemetry:timestamp(),
                                                        time=opentelemetry:timestamp(),
                                                        count = 3,
                                                        sum = 9,
                                                        bucket_counts = [1,1,1],
                                                        explicit_bounds = [0,3,5],
                                                        exemplars = [],
                                                        flags = 0,
                                                        min = 1,
                                                        max = 5
                                                       }]}}],
    Resource = otel_resource_env_var:get_resource([]),

    ?assertMatch(ok, opentelemetry_exporter:export(metrics, Metrics, Resource, State)),
    ok.

configuration(_Config) ->
    try
        %% Default conf
        ?assertEqual(#{endpoint => #{host => "localhost", path => "/v1/traces", port => 4318, scheme => "http"},
                       headers => [], protocol => http_protobuf, ssl_options => [], compression => undefined,
                       timeout_ms => 30000},
                     opentelemetry_exporter:init_conf(traces, #{})),
        %% Only grpc is implemented for logs and metrics, expecting it to be used by default,
        %% no default path must be set for grpc
        MetricsAndLogsDefaultExpected =
            #{endpoint => #{host => "localhost", path => [], port => 4317, scheme => "http"},
              headers => [], protocol => grpc, ssl_options => [], compression => undefined,
              timeout_ms => 30000},
        ?assertEqual(MetricsAndLogsDefaultExpected, opentelemetry_exporter:init_conf(logs, #{})),
        ?assertEqual(MetricsAndLogsDefaultExpected, opentelemetry_exporter:init_conf(metrics, #{})),

        ?assertMatch(#{endpoint := #{scheme := "http", host := "localhost", port := 9090, path := []},
                       protocol := http_protobuf,
                       ssl_options := [{cacertfile, "/etc/ssl/cert.pem"}]},
                     opentelemetry_exporter:init_conf(traces, #{endpoint => <<"http://localhost:9090">>,
                                                                ssl_options => [{cacertfile, "/etc/ssl/cert.pem"}]})),

        ?assertMatch(#{endpoint := #{scheme := "https", host := "localhost", port := 9090, path := "/v1/traces"},
                       ssl_options := [{cacertfile, "/etc/ssl/cert.pem"}]},
                     opentelemetry_exporter:init_conf(traces, #{endpoint => "https://localhost:9090/v1/traces",
                                                                ssl_options => [{cacertfile, "/etc/ssl/cert.pem"}]})),
        ?assertMatch(#{endpoint := #{scheme := "https", host := "localhost", port := 9090, path := []},
                       ssl_options := [{verify, verify_none}]},
                     opentelemetry_exporter:init_conf(traces,
                                                      #{endpoint => #{scheme => "https",
                                                                      host => "localhost",
                                                                      path => [], port => 9090},
                                                        ssl_options => [{verify, verify_none}]})),

        application:set_env(opentelemetry_exporter, ssl_options, [{cacertfile, "/etc/ssl/other.pem"}]),
        ?assertMatch(#{endpoint := #{host := "localhost", path := "/v1/traces", port := 4318, scheme := "http"},
                       ssl_options := [{cacertfile, "/etc/ssl/other.pem"}]},
                     opentelemetry_exporter:init_conf(traces, #{})),

        %% Opts passed to `opentelemetry_exporter:init_conf/2` must take precedence over app env
        ?assertMatch(#{endpoint := #{scheme := "https", host := "localhost", port := 9090, path := []},
                       ssl_options := [{cacertfile, "/etc/ssl/cert.pem"}]},
                     opentelemetry_exporter:init_conf(traces, #{endpoint => "https://localhost:9090",
                                                                ssl_options => [{cacertfile, "/etc/ssl/cert.pem"}]})),

        application:unset_env(opentelemetry_exporter, ssl_options),

        ?assertMatch(#{endpoint := #{scheme := "https", host := "localhost", port := 443, path := []},
                       ssl_options := [{cacertfile, "/etc/ssl/cert.pem"}]},
                     opentelemetry_exporter:init_conf(traces, #{endpoint => "https://localhost:443",
                                                                ssl_options => [{cacertfile, "/etc/ssl/cert.pem"}]})),

        ?assertMatch(#{endpoint := #{scheme := "https", host := "localhost", port := 443, path := []}},
                     opentelemetry_exporter:init_conf(logs, #{endpoint => <<"https://localhost:443">>})),

        ?assertMatch(#{endpoint := #{scheme := "https", host := "localhost", port := 443, path := []}},
                     opentelemetry_exporter:init_conf(metrics, #{endpoint => <<"https://localhost:443">>})),

        ?assertMatch(#{endpoint := #{scheme := "https", host := "localhost", port := 443, path := "/used/path"}},
                     opentelemetry_exporter:init_conf(traces, #{endpoint => <<"https://localhost/used/path">>})),

        ?assertMatch(#{endpoint := #{scheme := "http", host := "localhost", port := 80, path := []}},
                     opentelemetry_exporter:init_conf(traces, #{endpoint => "http://localhost"})),

        ?assertMatch(#{endpoint := {error, _}}, opentelemetry_exporter:init_conf(traces, #{endpoint => "://badendpoint"})),

        application:set_env(opentelemetry_exporter, otlp_endpoint, "http://localhost:5353"),
        ?assertMatch(#{endpoint := #{host := "localhost", path := "/v1/traces", port := 5353, scheme := "http"}},
                     opentelemetry_exporter:init_conf(traces, #{})),

        application:set_env(opentelemetry_exporter, otlp_traces_endpoint, "http://localhost:5353"),
        ?assertMatch(#{endpoint := #{host := "localhost", path := [], port := 5353,scheme := "http"}},
                     opentelemetry_exporter:init_conf(traces, #{})),
        application:unset_env(opentelemetry_exporter, otlp_traces_endpoint),

        application:set_env(opentelemetry_exporter, otlp_endpoint, "\"http://withextraquotes.com:5353\""),
        ?assertMatch(#{endpoint := {error, _}},
                     opentelemetry_exporter:init_conf(traces, #{})),

        application:set_env(opentelemetry_exporter, otlp_endpoint, <<"http://somehost:4317">>),
        application:set_env(opentelemetry_exporter, otlp_protocol, grpc),
        ?assertMatch(#{endpoint := #{scheme := <<"http">>, host := <<"somehost">>,
                                     port := 4317, path := <<>>},
                       protocol := grpc},
                     opentelemetry_exporter:init_conf(traces, #{})),

        application:unset_env(opentelemetry_exporter, otlp_protocol),
        application:unset_env(opentelemetry_exporter, otlp_endpoint),
        os:putenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://somehost:4317"),
        os:putenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc"),
        ?assertMatch(#{endpoint := #{scheme := "http", host := "somehost", port := 4317, path := []},
                       protocol := grpc},
                     opentelemetry_exporter:init_conf(traces, #{})),

        os:unsetenv("OTEL_EXPORTER_OTLP_PROTOCOL"),
        os:unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT"),

        os:putenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4343"),
        os:putenv("OTEL_EXPORTER_OTLP_HEADERS", "key1=value1"),
        ?assertMatch(#{endpoint :=
                           #{host := "localhost", path := "/v1/traces", port := 4343,
                             scheme := "http"},
                       headers := [{"key1", "value1"}],
                       protocol := http_protobuf
                      },
                     opentelemetry_exporter:init_conf(traces, #{})),

        os:putenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4343/internal"),
        os:putenv("OTEL_EXPORTER_OTLP_HEADERS", "key1=value1"),
        ?assertMatch(#{endpoint :=
                           #{host := "localhost", path := "/internal/v1/traces", port := 4343,
                            scheme := "http"},
                       headers := [{"key1", "value1"}],
                       compression := undefined,
                       protocol := http_protobuf},
                     opentelemetry_exporter:init_conf(traces, #{})),

        %% test all supported protocols
        application:unset_env(opentelemetry_exporter, otlp_protocol),
        os:putenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc"),
        ?assertMatch(#{protocol := grpc}, opentelemetry_exporter:init_conf(traces, #{})),
        ?assertMatch(#{protocol := grpc}, opentelemetry_exporter:init_conf(metrics, #{})),
        ?assertMatch(#{protocol := grpc}, opentelemetry_exporter:init_conf(logs, #{})),

        %% the specification defines the value as "http/protobuf"
        %% https://github.com/open-telemetry/opentelemetry-specification/blob/82707fd9f7b1266f1246b02ff3e00bebdee6b538/specification/protocol/exporter.md#specify-protocol
        application:unset_env(opentelemetry_exporter, otlp_protocol),
        os:putenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf"),
        ?assertMatch(#{protocol := http_protobuf},
                     opentelemetry_exporter:init_conf(traces, #{})),

        %% backwards compatible with earlier stable version that uses "http_protobuf"
        application:unset_env(opentelemetry_exporter, otlp_protocol),
        os:putenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http_protobuf"),
        ?assertMatch(#{protocol := http_protobuf},
                     opentelemetry_exporter:init_conf(traces, #{})),

        %% TRACES_ENDPOINT takes precedence
        os:putenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://localhost:5353/traces/path"),
        os:putenv("OTEL_EXPORTER_OTLP_TRACES_HEADERS", "key2=value2"),
        ?assertMatch(#{endpoint :=
                           #{host := "localhost", path := "/traces/path", port := 5353,
                             scheme := "http"},
                       headers := [{"key2", "value2"}],
                       compression := undefined,
                       protocol := http_protobuf},
                     opentelemetry_exporter:init_conf(traces, #{})),

        os:putenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc"),
        ?assertMatch(#{protocol := grpc},
                     opentelemetry_exporter:init_conf(traces, #{}))
    after
        os:unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
        os:unsetenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"),
        os:unsetenv("OTEL_EXPORTER_OTLP_HEADERS"),
        os:unsetenv("OTEL_EXPORTER_OTLP_TRACES_HEADERS"),
        os:unsetenv("OTEL_EXPORTER_OTLP_PROTOCOL")
    end.

ets_instrumentation_info(_Config) ->
    Tid = ets:new(span_tab, [duplicate_bag, {keypos, #span.instrumentation_scope}]),

    TraceId = otel_id_generator:generate_trace_id(),
    SpanId = otel_id_generator:generate_span_id(),

    Events1 = otel_events:new(128, 128, 128),
    ParentSpan =
        #span{name = <<"span-1">>,
              trace_id = TraceId,
              span_id = SpanId,
              kind = ?SPAN_KIND_CLIENT,
              start_time = opentelemetry:timestamp(),
              end_time = opentelemetry:timestamp(),
              links = otel_links:new([], 128, 128, 128),
              events = otel_events:add([#event{system_time_native=opentelemetry:timestamp(),
                                               name = <<"event-1">>,
                                               attributes = [{<<"attr-1">>, <<"value-1">>}]},
                                        #event{system_time_native=opentelemetry:timestamp(),
                                               name = <<"event-2">>,
                                               attributes = [{<<"attr-3">>, <<"value-3">>}]}], Events1),
              attributes = otel_attributes:new([{<<"attr-2">>, <<"value-2">>}], 128, 128),
              instrumentation_scope=#instrumentation_scope{name = <<"tracer-2">>,
                                                               version = <<"0.0.1">>}},
    true = ets:insert(Tid, ParentSpan),

    Events2 = otel_events:new(128, 128, 128),
    ChildSpan = #span{name = <<"span-2">>,
                      trace_id = TraceId,
                      span_id = otel_id_generator:generate_span_id(),
                      parent_span_id = SpanId,
                      kind = ?SPAN_KIND_SERVER,
                      start_time = opentelemetry:timestamp(),
                      end_time = opentelemetry:timestamp(),
                      links = otel_links:new([], 128, 128, 128),
                      events = otel_events:add([#event{system_time_native=opentelemetry:timestamp(),
                                                       name = <<"event-1">>,
                                                       attributes = [{<<"attr-1">>, <<"value-1">>}]},
                                                #event{system_time_native=opentelemetry:timestamp(),
                                                       name = <<"event-2">>,
                                                       attributes = [{<<"attr-3">>, <<"value-3">>}]}], Events2),
                      attributes = otel_attributes:new([{<<"attr-2">>, <<"value-2">>}], 128, 128),
                      instrumentation_scope=#instrumentation_scope{name = <<"tracer-1">>,
                                                                       version = <<"0.0.1">>}},
    true = ets:insert(Tid, ChildSpan),

    ?assertMatch([#{scope :=
                        #{name := <<"tracer-1">>,version := <<"0.0.1">>},
                    spans :=
                        [_]},
                  #{scope :=
                        #{name := <<"tracer-2">>,version := <<"0.0.1">>},
                    spans :=
                        [_]}], lists:sort(otel_otlp_traces:to_proto_by_instrumentation_scope(Tid))),

    ok.

span_round_trip(_Config) ->
    TraceId = otel_id_generator:generate_trace_id(),
    SpanId = otel_id_generator:generate_span_id(),

    Events = otel_events:new(128, 128, 128),
    Span =
        #span{name = <<"span-1">>,
              trace_id = TraceId,
              span_id = SpanId,
              kind = ?SPAN_KIND_CLIENT,
              tracestate = otel_tracestate:new([{"ts-attr-1", "ts-value-1"}]),
              start_time = opentelemetry:timestamp(),
              end_time = opentelemetry:timestamp(),
              links = otel_links:new([], 128, 128, 128),
              events = otel_events:add([#event{system_time_native=opentelemetry:timestamp(),
                                               name = <<"event-1">>,
                                               attributes = [{<<"attr-1">>, <<"value-1">>}]},
                                        #event{system_time_native=opentelemetry:timestamp(),
                                               name = event_2,
                                               attributes = [{<<"attr-3">>, <<"value-3">>}]}], Events),
              attributes = otel_attributes:new([{<<"attr-2">>, <<"value-2">>},
                                                {attr_3, true},
                                                {<<"map-key-1">>, #{<<"map-key-1">> => 123}},
                                                {<<"list-key-1">>, [3.14, 9.345]}
                                                ], 128, 128),
              status = #status{code=?OTEL_STATUS_OK,
                               message = <<"">>},
              instrumentation_scope = #instrumentation_scope{name = <<"tracer-1">>,
                                                             version = <<"0.0.1">>}},

    PbSpan = otel_otlp_traces:to_proto(Span),
    Proto = opentelemetry_exporter_trace_service_pb:encode_msg(PbSpan, span),

    PbSpan1 = maps:filter(fun(_, V) -> V =/= undefined end, PbSpan),
    DecodedProto = opentelemetry_exporter_trace_service_pb:decode_msg(Proto, span),
    ?assertEqual(maps:with([trace_id, span_id], DecodedProto),
                 maps:with([trace_id, span_id], PbSpan1)),

    ok.

%% insert a couple spans and export to locally running otel collector
verify_export(Config) ->
    os:putenv("OTEL_RESOURCE_ATTRIBUTES",
              "service.name=my-test-service,service.version=98da75ea6d38724743bf42b45565049238d86b3f"),
    Protocol = ?config(protocol, Config),
    Compression = ?config(compression, Config),

    Port = case Protocol of
               grpc ->
                   4317;
               http_protobuf ->
                   4318
           end,
    {ok, State} = opentelemetry_exporter:init(traces,
                                              exporter_test,
                                              #{protocol => Protocol,
                                                compression => Compression,
                                                endpoint => lists:concat(["http://localhost:",
                                                                          integer_to_list(Port),
                                                                          "/v1/traces"])
                                               }),

    case Protocol of
        grpc -> ok;
        _ ->
            %% regression test. adding the httpc profile meant that init'ing more than once would crash
            {ok, _State} = opentelemetry_exporter:init(traces,
                                                       exporter_test,
                                                       #{protocol => Protocol,
                                                         compression => Compression,
                                                         endpoint => #{scheme => <<"http">>,
                                                                       host => <<"localhost">>,
                                                                       port => Port,
                                                                       path => <<"v1/traces">>}})
    end,

    Tid = ets:new(span_tab, [duplicate_bag, {keypos, #span.instrumentation_scope}]),

    %% Tempoararily adding this because without this, we would face
    %% {error, no_endpoints} when attempt to export when we have more
    %% than 1 gprc test case.
    timer:sleep(500),
    ?assertMatch(ok, opentelemetry_exporter:export(traces, Tid, otel_resource:create([]), State)),

    TraceId = otel_id_generator:generate_trace_id(),
    SpanId = otel_id_generator:generate_span_id(),

    Events = otel_events:new(128, 128, 128),
    ParentSpan =
        #span{name = <<"span-1">>,
              trace_id = TraceId,
              span_id = SpanId,
              kind = ?SPAN_KIND_CLIENT,
              start_time = opentelemetry:timestamp(),
              end_time = opentelemetry:timestamp(),
              links = otel_links:new([], 128, 128, 128),
              events = otel_events:add([#event{system_time_native=opentelemetry:timestamp(),
                                               name = <<"event-1">>,
                                               attributes = otel_attributes:new([{<<"attr-1">>, <<"value-1">>}], 128, 128)},
                                        #event{system_time_native=opentelemetry:timestamp(),
                                               name = <<"event-2">>,
                                               attributes = otel_attributes:new([{<<"attr-3">>, <<"value-3">>}], 128, 128)}], Events),
              status = #status{code=?OTEL_STATUS_UNSET,
                               message = <<"hello I'm unset">>},
              instrumentation_scope = #instrumentation_scope{name = <<"tracer-1">>,
                                                             version = <<"0.0.1">>},
              attributes = otel_attributes:new([{<<"attr-2">>, <<"value-2">>}], 128, 128)},
    true = ets:insert(Tid, ParentSpan),

    Link1 = opentelemetry:link(?start_span(<<"linked-span">>)),

    ChildSpan = #span{name = <<"span-2">>,
                      trace_id = TraceId,
                      span_id = otel_id_generator:generate_span_id(),
                      parent_span_id = SpanId,
                      kind = ?SPAN_KIND_SERVER,
                      start_time = opentelemetry:timestamp(),
                      end_time = opentelemetry:timestamp(),
                      links = otel_links:new([Link1], 128, 128, 128),
                      events = otel_events:add([#event{system_time_native=opentelemetry:timestamp(),
                                                       name = <<"event-1">>,
                                                       attributes = otel_attributes:new([{<<"attr-1">>, <<"value-1">>}], 128, 128)},
                                                #event{system_time_native=opentelemetry:timestamp(),
                                                       name = <<"event-2">>,
                                                       attributes = otel_attributes:new([{<<"attr-3">>, <<"value-3">>}], 128, 128)}], Events),
                      status = #status{code=?OTEL_STATUS_ERROR,
                                       message = <<"hello I'm an error">>},
                      instrumentation_scope = #instrumentation_scope{name = <<"tracer-1">>,
                                                                     version = <<"0.0.1">>},
                      attributes = otel_attributes:new([
                                                        {atom_attr, atom_value},
                                                        {<<"attr-2">>, <<"value-2">>},
                                                        {<<"map-key-1">>, #{<<"map-key-1">> => 123}},
                                                        {<<"proplist-key-1">>, [{proplistkey1, 456}, {<<"proplist-key-2">>, 9.345}]},
                                                        {<<"list-key-1">>, [listkey1, 123, <<"list-value-3">>]},
                                                        {<<"tuple-key-1">>, {a, 123, [456, {1, 2}]}}
                                                       ], 128, 128)},
    true = ets:insert(Tid, ChildSpan),

    ?assertMatch([#{spans := [_, _]}],
                 otel_otlp_traces:to_proto_by_instrumentation_scope(Tid)),
    Resource = otel_resource_env_var:get_resource([]),
    ?assertEqual(otel_attributes:new([{'service.name',<<"my-test-service">>},
                                      {'service.version',<<"98da75ea6d38724743bf42b45565049238d86b3f">>}], 128, 255),
                 otel_resource:attributes(Resource)),
    ?assertMatch(ok, opentelemetry_exporter:export(traces, Tid, Resource, State)),

    ok.
