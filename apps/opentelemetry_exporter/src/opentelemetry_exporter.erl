%%%------------------------------------------------------------------------
%% Copyright 2021, OpenTelemetry Authors
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
%% @doc This is the module providing the OpenTelemetry protocol for
%% exporting traces. It can be configured through its application
%% environment, the OS environment or directly through a map of options
%% passed when setting up the exporter in the batch processor.
%%
%% `opentelemetry_exporter' application environment options are:
%%
%% <ul>
%%   <li>
%%     `otlp_endpoint': The URL to send traces and metrics to, for traces the
%%     path `v1/traces' is appended to the path in the URL.
%%   </li>
%%   <li>
%%     `otlp_traces_endpoint': URL to send only traces to. This takes precedence
%%     for exporting traces and the path of the URL is kept as is, no suffix is
%%     appended.
%%   </li>
%%   <li>
%%     `otlp_headers': List of additional headers (`[{unicode:chardata(), unicode:chardata()}]') to add to export requests.
%%   </li>
%%   <li>
%%     `otlp_traces_headers': Additional headers (`[{unicode:chardata(), unicode:chardata()}]') to add to only trace export requests.
%%   </li>
%%   <li>
%%     `otlp_protocol': The transport protocol, supported values: `grpc' and `http_protobuf'. Defaults to `http_protobuf'.
%%   </li>
%%   <li>
%%     `otlp_traces_protocol': The transport protocol to use for exporting traces, supported values: `grpc' and `http_protobuf'. Defaults to `http_protobuf'
%%   </li>
%%   <li>
%%     `otlp_compression': Compression type to use, supported values: `gzip'. Defaults to no compression.
%%   </li>
%%   <li>
%%     `otlp_traces_compression': Compression type to use for exporting traces, supported values: `gzip'. Defaults to no compression.
%%   </li>
%% </ul>
%%
%% There also corresponding OS environment variables can also set those
%% configuration values:
%%
%% <ul>
%%   <li>`OTEL_EXPORTER_OTLP_ENDPOINT': The URL to send traces and metrics to, for traces the path `v1/traces' is appended to the path in the URL.</li>
%%   <li>`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT': URL to send only traces to. This takes precedence for exporting traces and the path of the URL is kept as is, no suffix is appended.</li>
%%   <li>`OTEL_EXPORTER_OTLP_HEADERS': List of additional headers to add to export requests.</li>
%%   <li>`OTEL_EXPORTER_OTLP_TRACES_HEADERS': Additional headers to add to only trace export requests.</li>
%%   <li>`OTEL_EXPORTER_OTLP_PROTOCOL': The transport protocol to use, supported values: `grpc' and `http_protobuf'. Defaults to `http_protobuf'.</li>
%%   <li>`OTEL_EXPORTER_OTLP_TRACES_PROTOCOL': The transport protocol to use for exporting traces, supported values: `grpc' and `http_protobuf'. Defaults to `http_protobuf'.</li>
%%   <li>`OTEL_EXPORTER_OTLP_COMPRESSION': Compression to use, supported value: gzip. Defaults to no compression.</li>
%%   <li>`OTEL_EXPORTER_OTLP_TRACES_COMPRESSION': Compression to use when exporting traces, supported value: gzip. Defaults to no compression.</li>
%% </ul>
%%
%% You can also set these configuration values in the map passed to the
%% opentelemetry processor configuration.
%% <ul>
%%   <li>`endpoints': A list of endpoints to send traces to. Can take one of the forms described below. By default, exporter sends data to `http://localhost:4318'.</li>
%%   <li>`headers': List of additional headers to add to export requests.</li>
%%   <li>`protocol': The transport protocol to use, supported values: `grpc' and `http_protobuf'. Defaults to `http_protobuf'.</li>
%%   <li>`compression': Compression to use, supported value: `gzip'. Defaults to no compression.</li>
%%   <li>`ssl_options': a list of SSL options.  See Erlang's <a href='https://www.erlang.org/doc/man/ssl.html#TLS/DTLS%20OPTION%20DESCRIPTIONS%20-%20CLIENT'>SSL docs</a> for what options are available.</li>
%% </ul>
%%
%% Endpoints configuration
%%
%% You can pass your collector endpoints in three forms:
%%
%% <ul>
%%   <li> As a string, i.e `"https://localhost:4000"'.</li>
%%   <li> As a map, with the following keys:
%%     <ul>
%%       <li>`host => unicode:chardata()'</li>
%%       <li>`path => unicode:chardata()'</li>
%%       <li>`port => integer() >= 0 | undefined'</li>
%%       <li>`scheme => unicode:chardata()'</li>
%%     </ul>
%%   </li>
%%   <li> As a 4 element tuple in format `{Scheme, Host, Port, SSLOptions}'.</li>
%% </ul>
%%
%% While using `http_protobuf' protocol, currently only the first endpoint in that list is used to export traces, the rest is effectively ignored. `grpc' supports multiple endpoints.
%%
%% @end
%%%-------------------------------------------------------------------------
-module(opentelemetry_exporter).

-export([init/3,
         export/4,
         shutdown/1]).

-ifdef(TEST).
-export([init_conf/2]).
-endif.

-define(DEFAULT_HTTP_PORT, 4318).
-define(DEFAULT_HTTP_ENDPOINT, #{host => "localhost",
                                 path => [],
                                 port => ?DEFAULT_HTTP_PORT,
                                 scheme => "http"}).
-define(DEFAULT_GRPC_PORT, 4317).
-define(DEFAULT_GRPC_ENDPOINT, #{host => "localhost",
                                 path => [],
                                 port => ?DEFAULT_GRPC_PORT,
                                 scheme => "http"}).
-define(DEFAULT_TIMEOUT_MS, 30_000).
-define(DEFAULT_PATHS, #{traces => "v1/traces",
                         metrics => "v1/metrics",
                         logs => "v1/logs"}).
-define(signal_opt_name(_Parts_), list_to_existing_atom(lists:concat(lists:join("_", _Parts_)))).

-type headers() :: [{unicode:chardata(), unicode:chardata()}].
-type endpoint() :: uri_string:uri_string() | uri_string:uri_map().
-type protocol() :: grpc | http_protobuf | http_json.
-type compression() :: gzip | undefined.
-type opts() :: #{endpoint => endpoint(),
                  headers => headers(),
                  protocol => protocol(),
                  ssl_options => [ssl:tls_client_option()],
                  compression => compression(),
                  timeout_ms => pos_integer()}.

-export_type([opts/0,
              headers/0,
              endpoint/0,
              protocol/0]).

-record(state, {httpc_profile :: atom() | undefined,
                protocol :: protocol(),
                channel :: term(),
                channel_pid :: pid() | undefined,
                headers :: headers(),
                compression :: compression() | undefined,
                grpc_metadata :: map() | undefined,
                endpoint :: endpoint(),
                ssl_options :: [ssl:tls_client_option()],
                timeout_ms = ?DEFAULT_TIMEOUT_MS :: non_neg_integer(),
                exporter_id :: atom()}).

-include_lib("opentelemetry_api/include/gradualizer.hrl").

%%--------------------------------------------------------------------
%% Exporter behaviour
%%--------------------------------------------------------------------

%% @doc Initialize the exporter based on the provided configuration.
-spec init(otel_exporter:otel_signal(), atom(), opts()) -> {ok, #state{}} | {error, term()}.
init(OtelSignal, ExporterId, Opts) when OtelSignal =:= traces;
                                        OtelSignal =:= metrics;
                                        OtelSignal =:= logs ->
    #{protocol := Proto,
      endpoint := Endpoint,
      headers := Headers,
      compression := Compression,
      ssl_options := SSLOptions,
      timeout_ms := TimeoutMs} = init_conf(OtelSignal, Opts),
    case recompose_endpoint(Endpoint) of
        {error, Reason} ->
            {error, {invalid_endpoint, Reason}};
        URL ->
            State = #state{exporter_id=ExporterId,
                           protocol=Proto,
                           endpoint=URL,
                           ssl_options=SSLOptions,
                           timeout_ms=TimeoutMs,
                           headers=Headers,
                           compression=Compression},
            init_by_proto(Proto, State)
    end.

%% @doc Export OTLP protocol telemery data to the configured endpoints.
export(traces, _Tab, _Resource, #state{protocol=http_json}) ->
    {error, unimplemented};
export(traces, Tab, Resource, #state{protocol=http_protobuf,
                                     httpc_profile=HttpcProfile,
                                     headers=Headers,
                                     compression=Compression,
                                     timeout_ms=TimeoutMs,
                                     endpoint=URL,
                                     ssl_options=SSLOptions}) ->
    case otel_otlp_traces:to_proto(Tab, Resource) of
        empty ->
            ok;
        ProtoMap ->
            Proto = opentelemetry_exporter_trace_service_pb:encode_msg(ProtoMap,
                                                                       export_trace_service_request),
            {NewHeaders, NewProto} =
                case Compression of
                    gzip -> {[{"content-encoding", "gzip"} | Headers], zlib:gzip(Proto)};
                    _ -> {Headers, Proto}
                end,
            case httpc:request(post, {URL, NewHeaders, "application/x-protobuf", NewProto},
                               [{ssl, SSLOptions}, {timeout, TimeoutMs}], [], HttpcProfile) of
                {ok, {{_, Code, _}, _, _}} when Code >= 200 andalso Code =< 202 ->
                    ok;
                {ok, {{_, Code, _}, _, Message}} ->
                    {error, {Code, Message}};
                {error, Reason} ->
                    {error, Reason}
            end
    end;
export(traces, Tab, Resource, #state{protocol=grpc,
                                     grpc_metadata=Metadata,
                                     channel=Channel,
                                     timeout_ms=TimeoutMs}) ->
    case otel_otlp_traces:to_proto(Tab, Resource) of
        empty ->
            ok;
        ExportRequest ->
            Opts = #{channel => Channel, timeout => TimeoutMs},
            case opentelemetry_trace_service:export(ExportRequest, Metadata, Opts) of
                {ok, _Response, _ResponseMetadata} ->
                    ok;
                {error, Reason} ->
                    {error, Reason}

            end
    end;
export(metrics, Tab, Resource, #state{protocol=grpc,
                                      grpc_metadata=Metadata,
                                      channel=Channel,
                                      timeout_ms=TimeoutMs}) ->
    ExportRequest = otel_otlp_metrics:to_proto(Tab, Resource),
    Opts = #{channel => Channel, timeout => TimeoutMs},
    case opentelemetry_metrics_service:export(ExportRequest, Metadata, Opts) of
        {ok, _Response, _ResponseMetadata} ->
            ok;
        {error, Reason} ->
            {error, Reason}
    end;
export(logs, {Tab, Config}, Resource, #state{channel=Channel,
                                             protocol=grpc,
                                             grpc_metadata=Metadata,
                                             timeout_ms=TimeoutMs}) ->
    case otel_otlp_logs:to_proto(Tab, Resource, Config) of
        empty ->
            ok;
        ExportRequest ->
            Opts = #{channel => Channel, timeout => TimeoutMs},
            case opentelemetry_logs_service:export(ExportRequest, Metadata, Opts) of
                {ok, _Response, _ResponseMetadata} ->
                    ok;
                {error, Reason} ->
                    {error, Reason}
            end
    end;
export(_, _Tab, _Resource, _State) ->
    {error, unimplemented}.

%% @doc Shutdown the exporter.
shutdown(#state{channel_pid=undefined}) ->
    ok;
shutdown(#state{channel=Channel}) ->
    %% if gproc is already stopped (e.g. during shutdown),
    %% `grpc_client_sup:stop_channel_pool/1` can crash with badarg
    try
        _ = grpc_client_sup:stop_channel_pool(Channel)
    catch
        _:_ -> ok
    end,
    ok.

%%--------------------------------------------------------------------
%% Internal functions
%%--------------------------------------------------------------------

init_conf(OtelSignal, Opts) ->
    EnvOpts = app_env_opts(),
    DefaultProto = case OtelSignal of
                       traces -> http_protobuf;
                       %% only grpc exporter is implemented for other siganls
                       _ -> grpc
                   end,
    Proto = get_opt(protocol, OtelSignal, Opts, EnvOpts, DefaultProto),
    DefaultEndpoint = case Proto of
                          grpc -> ?DEFAULT_GRPC_ENDPOINT;
                          _  -> add_default_path(OtelSignal, ?DEFAULT_HTTP_ENDPOINT)
                      end,
    #{protocol => Proto,
      endpoint => get_opt(endpoint, OtelSignal, Opts, EnvOpts, DefaultEndpoint, Proto),
      headers => get_opt(headers, OtelSignal, Opts, EnvOpts, []),
      compression => get_opt(compression, OtelSignal, Opts, EnvOpts, undefined),
      ssl_options => get_opt(ssl_options, OtelSignal, Opts, EnvOpts, []),
      timeout_ms => get_opt(timeout_ms, OtelSignal, Opts, EnvOpts, ?DEFAULT_TIMEOUT_MS)}.

%% OTEL_EXPORTER_OTLP_<signal>_ENDPOINT must be used as,
%% OTEL_EXPORTER_OTLP_ENDPOINT is used as a base URL, default path must be appended to it
maybe_modify_opt(false = _IsSignalOpt, true = _IsEnvOpt, Proto, otlp_endpoint, OtelSignal,
                 Endpoint) when Proto =/= grpc ->
    add_default_path(OtelSignal, Endpoint);
%% timeout from env is set in seconds and needs to be converted to milliseconds
maybe_modify_opt(_IsSignalOpt, true = _IsEnvOpt, _Proto, otlp_timeout, _OtelSignal, TimeoutSec) ->
    timer:seconds(TimeoutSec);
maybe_modify_opt(_IsSignalOpt, _IsEnvOpt, _Proto, _OptName, _OtelSignal, Val) ->
    Val.

get_opt(OptName, OtelSignal, Opts, Env, Default) ->
    get_opt(OptName, OtelSignal, Opts, Env, Default, undefined).

get_opt(OptName, OtelSignal, Opts, Env, Default, Proto) ->
    EnvOptName = env_opt_name(OptName),
    {RawVal, IsSignalOpt, IsEnvOpt} =
        %% directly passed options take precedence over app/ENV variables
        case Opts of
            #{OptName := Val} when Val =/= undefined ->
                {Val, false, false};
            _ ->
                SignalOptName = signal_opt_name(EnvOptName, OtelSignal),
                case Env of
                    #{SignalOptName := Val} when Val =/= undefined ->
                        {Val, true, true};
                    #{EnvOptName := Val} when Val =/= undefined ->
                        {Val, false, true};
                    _ ->
                        {Default, false, false}
                end
        end,
    ParsedVal = parse_opt_val(OptName, RawVal),
    maybe_modify_opt(IsSignalOpt, IsEnvOpt, Proto, EnvOptName, OtelSignal, ParsedVal).

signal_opt_name(otlp_endpoint, OtelSignal) ->
    ?signal_opt_name(["otlp", OtelSignal, "endpoint"]);
signal_opt_name(otlp_headers, OtelSignal) ->
    ?signal_opt_name(["otlp", OtelSignal, "headers"]);
signal_opt_name(otlp_protocol, OtelSignal) ->
    ?signal_opt_name(["otlp", OtelSignal, "protocol"]);
signal_opt_name(otlp_compression, OtelSignal) ->
    ?signal_opt_name(["otlp", OtelSignal, "compression"]);
signal_opt_name(otlp_timeout, OtelSignal) ->
    ?signal_opt_name(["otlp", OtelSignal, "timeout"]);
signal_opt_name(ssl_options, OtelSignal) ->
    ?signal_opt_name([OtelSignal, "ssl_options"]);
signal_opt_name(_, _OtelSignal) ->
    undefined.

env_opt_name(timeout_ms) ->
    otlp_timeout;
env_opt_name(ssl_options) ->
    ssl_options;
env_opt_name(PlainOptName) ->
    list_to_existing_atom(lists:concat(["otlp_", PlainOptName])).

parse_opt_val(endpoint, RawVal) ->
    parse_endpoint(RawVal);
parse_opt_val(headers, RawVal) ->
    headers(RawVal);
parse_opt_val(_OptName, Val) ->
    Val.

add_default_path(OtelSignal, #{path := Path} = Endpoint) ->
    Endpoint#{path => filename:join(Path, maps:get(OtelSignal, ?DEFAULT_PATHS))};
%% Invalid endpoint can be ignored here, it will be handled afterwards
add_default_path(_OtelSignal, InvalidEndpoint) ->
    InvalidEndpoint.

init_by_proto(grpc, State) ->
    #state{compression=Compression,
           endpoint=Endpoint,
           exporter_id=ExporterId,
           headers=Headers,
           ssl_options=SSLOptions} = State,
    ChannelOpts = case Compression of
                      undefined -> #{};
                      Encoding -> #{encoding => Encoding}
                  end,
    ChannelOpts1 = case is_ssl(Endpoint) of
                       true ->
                           ChannelOpts#{gun_opts => #{transport => ssl,
                                                      transport_opts => SSLOptions}};
                       false ->
                           ChannelOpts
                   end,
    State1 = State#state{grpc_metadata = headers_to_grpc_metadata(Headers)},
    case grpc_client_sup:create_channel_pool(ExporterId,
                                             Endpoint,
                                             ChannelOpts1) of
        {ok, ChannelPid} ->
            {ok, State1#state{channel_pid=ChannelPid, channel=ExporterId}};
        {error, {already_started, _}} ->
            %% Reusing an existing client is not safe, as the config/endpoint can be changed,
            %% thus, it is restarted.
            %% Using unique exporter IDs is absolutely required, otherwise, one exporter instance
            %% can stop grpc client of another exporter.
            restart_grpc_client(ExporterId, Endpoint, ChannelOpts1, State1);
        Error -> Error
    end;
init_by_proto(HTTP, State) when HTTP =:= http_protobuf; HTTP =:= http_json ->
    HttpcProfile = start_httpc(State),
    {ok, State#state{httpc_profile=HttpcProfile}}.

%% Only called on a parsed and recomposed URL which is guaranteed to be a string
is_ssl("https://" ++ _) -> true;
is_ssl(_) -> false.

%% use a unique httpc profile per exporter
start_httpc(State) ->
    #state{exporter_id=ExporterId} = State,
    case httpc:info(ExporterId) of
        {error, {not_started, _}} ->
            %% by default use inet6fb4 which will try ipv6 and then fallback to ipv4 if it fails
            HttpcOptions = [{ipfamily, inet6fb4}],
            {ok, Pid} = inets:start(httpc, [{profile, ExporterId}]),
            ok = httpc:set_options(HttpcOptions, Pid);
        _ ->
            %% profile already started
            ok
    end,
    ExporterId.

restart_grpc_client(ExporterId, Endpoint, ChannelOpts, State) ->
    case grpc_client_sup:stop_channel_pool(ExporterId) of
        ok ->
            case grpc_client_sup:create_channel_pool(ExporterId, Endpoint, ChannelOpts) of
                {ok, ChannelPid} ->
                    {ok, State#state{channel_pid=ChannelPid, channel=ExporterId}};
                Error ->
                    Error
            end;
        Error ->
            Error
    end.

headers_to_grpc_metadata(Headers) ->
    lists:foldl(fun({X, Y}, Acc) ->
                        Acc#{unicode:characters_to_binary(X) => unicode:characters_to_binary(Y)}
                end, #{}, Headers).

%% make all headers into list strings
headers(List) when is_list(List) ->
    Headers = [{unicode:characters_to_list(X), unicode:characters_to_list(Y)} || {X, Y} <- List],
    add_user_agent(Headers);
headers(_) ->
    add_user_agent([]).

add_user_agent(Headers) ->
    case lists:search(fun({Header, _}) -> string:to_lower(Header) == "user-agent" end, Headers) of
        {value, _} -> Headers;
        false -> [{"user-agent", user_agent()} | Headers]
    end.

user_agent() ->
    {ok, ExporterVsn} = application:get_key(opentelemetry_exporter, vsn),
    lists:flatten(io_lib:format("OTel-OTLP-Exporter-erlang/~s", [ExporterVsn])).

recompose_endpoint(Endpoint) ->
    case parse_endpoint(Endpoint) of
        {error, _} = Err ->
            Err;
        Parsed ->
            %% Don't use `uri_string:normalize/1` because it removes default http/https port,
            %% but the port is required by grpc client lib
            case uri_string:recompose(Parsed) of
                {error, Reason, Info} ->
                    {error, {Reason, Info}};
                URL ->
                    to_list(URL)
            end
    end.

parse_endpoint(Endpoint=#{host := _Host, scheme := _Scheme, path := _Path}) ->
    maybe_add_scheme_port(Endpoint);
parse_endpoint(String) when is_list(String); is_binary(String) ->
    case to_list(String) of
        {error, _} = Err -> Err;
        UnicodeList ->
            case uri_string:parse(UnicodeList) of
                {error, Reason, Message} ->
                    {error, {Reason, Message}};
                #{scheme := _, host := _, path := _} = ParsedUri ->
                    maybe_add_scheme_port(ParsedUri);
                Other ->
                    {error, {invalid_url, Other}}
            end
    end;
parse_endpoint(Other) ->
    {error, {invalid_url, Other}}.

maybe_add_scheme_port(Uri=#{port := _Port}) ->
    Uri;
maybe_add_scheme_port(Uri=#{scheme := HTTP}) when HTTP =:= "http"; HTTP =:= <<"http">>  ->
    Uri#{port => 80};
maybe_add_scheme_port(Uri=#{scheme := HTTPS}) when HTTPS =:= "https"; HTTPS =:= <<"https">> ->
    Uri#{port => 443};
%% an unknown scheme
maybe_add_scheme_port(Uri) ->
    Uri.

to_list(Data) ->
    case unicode:characters_to_list(Data) of
        {incomplete, _, _} = Incomplete -> {error, Incomplete};
        {error, Encoded, Rest} -> {error, {Encoded, Rest}};
        UnicodeList -> UnicodeList
    end.

app_env_opts() ->
    ConfigMapping = config_mapping(),
    Config = lists:foldl(fun({_EnvVar, OptName, _Type}, Acc) -> Acc#{OptName => undefined} end,
                         #{},
                         ConfigMapping),
    AppEnv = application:get_all_env(opentelemetry_exporter),
    otel_configuration:merge_list_with_environment(ConfigMapping, AppEnv, Config).

config_mapping() ->
    [
     %% endpoint the Otel protocol exporter should connect to
     {"OTEL_EXPORTER_OTLP_ENDPOINT", otlp_endpoint, url},
     {"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", otlp_traces_endpoint, url},
     {"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", otlp_metrics_endpoint, url},
     {"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", otlp_logs_endpoint, url},

     %% headers to include in requests the exporter makes over the Otel protocol
     {"OTEL_EXPORTER_OTLP_HEADERS", otlp_headers, key_value_list},
     {"OTEL_EXPORTER_OTLP_TRACES_HEADERS", otlp_traces_headers, key_value_list},
     {"OTEL_EXPORTER_OTLP_METRICS_HEADERS", otlp_metrics_headers, key_value_list},
     {"OTEL_EXPORTER_OTLP_LOGS_HEADERS", otlp_logs_headers, key_value_list},

     {"OTEL_EXPORTER_OTLP_PROTOCOL", otlp_protocol, otlp_protocol},
     {"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", otlp_traces_protocol, otlp_protocol},
     {"OTEL_EXPORTER_OTLP_METRICS_PROTOCOL", otlp_metrics_protocol, otlp_protocol},
     {"OTEL_EXPORTER_OTLP_LOGS_PROTOCOL", otlp_logs_protocol, otlp_protocol},

     {"OTEL_EXPORTER_OTLP_COMPRESSION", otlp_compression, existing_atom},
     {"OTEL_EXPORTER_OTLP_TRACES_COMPRESSION", otlp_traces_compression, existing_atom},
     {"OTEL_EXPORTER_OTLP_METRICS_COMPRESSION", otlp_metrics_compression, existing_atom},
     {"OTEL_EXPORTER_OTLP_LOGS_COMPRESSION", otlp_logs_compression, existing_atom},

     %% {"OTEL_EXPORTER_OTLP_CERTIFICATE", otlp_certificate, path},
     %% {"OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE", otlp_traces_certificate, path},
     %% {"OTEL_EXPORTER_OTLP_METRICS_CERTIFICATE", otlp_metrics_certificate, path},

     {"OTEL_EXPORTER_OTLP_TIMEOUT", otlp_timeout, integer},
     {"OTEL_EXPORTER_OTLP_TRACES_TIMEOUT", otlp_traces_timeout, integer},
     {"OTEL_EXPORTER_OTLP_METRICS_TIMEOUT", otlp_metrics_timeout, integer},
     {"OTEL_EXPORTER_OTLP_LOGS_TIMEOUT", otlp_logs_timeout, integer},

     {"OTEL_EXPORTER_SSL_OPTIONS", ssl_options, key_value_list},
     {"OTEL_EXPORTER_TRACES_SSL_OPTIONS", traces_ssl_options, key_value_list},
     {"OTEL_EXPORTER_METRICS_SSL_OPTIONS", metrics_ssl_options, key_value_list},
     {"OTEL_EXPORTER_LOGS_SSL_OPTIONS", logs_ssl_options, key_value_list}
    ].
