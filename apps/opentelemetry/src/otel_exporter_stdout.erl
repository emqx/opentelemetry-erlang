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
%% @doc Exporter that prints spans to stdout.
%% @end
%%%-----------------------------------------------------------------------
-module(otel_exporter_stdout).

-behaviour(otel_exporter).

-export([init/3,
         export/4,
         shutdown/1]).

init(_OtelSignal, _ExporterId, _) ->
    {ok, []}.

export(_, SpansTid, _Resource, _) ->
    io:format("*SPANS FOR DEBUG*~n"),
    ets:foldl(fun(Span, _Acc) ->
                      io:format("~p~n", [Span])
              end, [], SpansTid),
    ets:delete_all_objects(SpansTid),
    ok.

shutdown(_) ->
    ok.
