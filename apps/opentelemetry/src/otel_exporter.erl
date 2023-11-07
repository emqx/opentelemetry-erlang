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
%% @doc
%% @end
%%%-----------------------------------------------------------------------
-module(otel_exporter).

-export([init/3,
         export_traces/4,
         export_metrics/4,
         export_logs/4,
         shutdown/1]).

-export_type([otel_signal/0]).

-type otel_signal() :: traces | metrics | logs.

%% Do any initialization of the exporter here and return configuration
%% that will be passed along with a list of spans to the `export' function.
-callback init(otel_signal(), ExporterId, Config) ->
    {ok, ExporterState} | {error, Reason} | ignore when
      ExporterId :: atom(),
      Config :: term(),
      ExporterState :: term(),
      Reason :: term().

%% This function is called when the configured interval expires with any
%% spans that have been collected so far and the configuration returned in `init'.
%% Do whatever needs to be done to export each span here, the caller will block
%% until it returns.
-callback export(otel_signal(), ets:tab(), otel_resource:t(), ExporterState) ->
    ok | {error, Reason} when
      ExporterState :: term(),
      Reason :: term().

-callback shutdown(State) -> ok when State :: term().

-include_lib("kernel/include/logger.hrl").

init(OtelSignal, ExporterId, {ExporterModule, Config}) when is_atom(ExporterModule),
                                                            is_atom(ExporterId) ->
    try ExporterModule:init(OtelSignal, ExporterId, Config) of
        {ok, ExporterState} ->
            ?LOG_INFO("~p ~p exporter successfully initialized", [OtelSignal, ExporterModule]),
            {ExporterModule, ExporterState};
        {error, Reason} ->
            ?LOG_ERROR("~p ~p exporter failed to initalize, error: ~p",
                       [OtelSignal, ExporterModule, Reason]),
            undefined;
        ignore ->
            undefined
    catch
        Class:Reason:St ->
            %% logging in debug level since config argument in stacktrace could have secrets
            ?LOG_ERROR("~p ~p exporter failed to initialize with exception: ~p:~p, stacktrace: ~p",
                       [OtelSignal, ExporterModule, Class, Reason,
                        otel_utils:stack_without_args(St)]),
            undefined
    end;
init(_OtelSignal, _ExporterId, Exporter) when Exporter =:= none ; Exporter =:= undefined ->
    undefined;
init(OtelSignal, ExporterId, ExporterModule) when is_atom(ExporterModule) ->
    init(OtelSignal, ExporterId, {ExporterModule, []}).

export_traces(ExporterModule, SpansTid, Resource, ExporterState) ->
    export(traces, ExporterModule, SpansTid, Resource, ExporterState).

export_metrics(ExporterModule, MetricsTid, Resource, ExporterState) ->
    export(metrics, ExporterModule, MetricsTid, Resource, ExporterState).

export_logs(ExporterModule, LogsTidAndHandlerConfig, Resource, ExporterState) ->
    export(logs, ExporterModule, LogsTidAndHandlerConfig, Resource, ExporterState).

shutdown(undefined) ->
    ok;
shutdown({ExporterModule, Config}) ->
    ExporterModule:shutdown(Config).

%%--------------------------------------------------------------------
%% Internal functions
%%--------------------------------------------------------------------

export(OtelSignal, ExporterModule, Tid, Resource, ExporterState) ->
    case ExporterModule:export(OtelSignal, Tid, Resource, ExporterState) of
        ok -> ok;
        {error, Reason} ->
            ?LOG_WARNING("~p failed to export ~p, reason: ~p", [ExporterModule, OtelSignal, Reason]),
            {error, Reason}
    end.

