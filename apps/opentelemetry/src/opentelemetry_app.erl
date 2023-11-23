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
%%%-------------------------------------------------------------------------
-module(opentelemetry_app).

-behaviour(application).

-export([start/2,
         stop/1]).

-include_lib("opentelemetry_api/include/opentelemetry.hrl").

start(_StartType, _StartArgs) ->
    #{start_default_tracer := StartDefaultTracer} = Config =
        otel_configuration:merge_with_os(application:get_all_env(opentelemetry)),

    SupResult = opentelemetry_sup:start_link(Config),
    _ = case StartDefaultTracer of
            true -> opentelemetry:start_default_tracer_provider();
            false -> ok
        end,
    SupResult.

stop(_State) ->
    _ = opentelemetry:cleanup_persistent_terms(),
    _ = otel_span_limits:cleanup_persistent_terms(),
    ok.
