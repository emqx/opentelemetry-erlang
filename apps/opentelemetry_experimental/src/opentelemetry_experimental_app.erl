%%%-------------------------------------------------------------------
%% @doc opentelemetry_experimental public API
%% @end
%%%-------------------------------------------------------------------

-module(opentelemetry_experimental_app).

-behaviour(application).

-export([start/2,
         stop/1,
         start_default_metrics/0,
         stop_default_metrics/0]).

-include_lib("opentelemetry_api_experimental/include/otel_meter.hrl").

start(_StartType, _StartArgs) ->
    Config = otel_configuration:merge_with_os(
               application:get_all_env(opentelemetry_experimental)),

    {ok, Pid} = opentelemetry_experimental_sup:start_link(Config),


    {ok, _} = start_default_metrics(Config),

   {ok, Pid}.

stop(_State) ->
    _ = opentelemetry_experimental:cleanup_persistent_terms(),
    ok.

-spec start_default_metrics() -> supervisor:startchild_ret().
start_default_metrics() ->
    Config = otel_configuration:merge_with_os(
               application:get_all_env(opentelemetry_experimental)),
    start_default_metrics(Config).

-spec stop_default_metrics() -> ok | {error, Reason :: atom()}.
stop_default_metrics() ->
    otel_meter_provider_sup:stop(?GLOBAL_METER_PROVIDER_NAME).

%% internal functions

start_default_metrics(Config) ->
    Resource = otel_resource_detector:get_resource(),
    otel_meter_provider_sup:start(?GLOBAL_METER_PROVIDER_NAME, Resource, Config).
