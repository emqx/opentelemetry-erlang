%%%------------------------------------------------------------------------
%% Copyright 2022, OpenTelemetry Authors
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
-module(otel_tracer_provider_sup).

-behaviour(supervisor).

-export([start_link/0,
         start/2,
         start/3,
         stop/1]).

-export([init/1]).

-define(SERVER, ?MODULE).
-define(sup_safe(_Action_),
        try
            _Action_
        catch
            exit:{noproc, _} ->
                %% no tracer provider sup is started, the sdk is probably disabled
                {error, no_tracer_provider_supervisor}
        end).

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%% here to support deprecated function `opentelemetry:start_tracer_provider/2'
start(Name, Config) ->
    start(Name, otel_resource:create([]), Config).

start(Name, Resource, Config) ->
    ?sup_safe(supervisor:start_child(?MODULE, child_spec(Name, Resource, Config))).

stop(Name) ->
    ?sup_safe(case supervisor:terminate_child(?MODULE, Name) of
                  ok ->
                      supervisor:delete_child(?MODULE, Name);
                  Err ->
                      Err
              end).

init([]) ->
    SupFlags = #{strategy => one_for_one,
                 intensity => 1,
                 period => 5},
    {ok, {SupFlags, []}}.


child_spec(Name, Resource, Config) ->
    #{id => Name,
      start => {otel_tracer_server_sup, start_link, [Name, Resource, Config]},
      restart => permanent,
      type => supervisor,
      modules => [otel_tracer_server_sup]}.
