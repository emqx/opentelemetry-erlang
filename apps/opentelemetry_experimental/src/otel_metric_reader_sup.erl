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
-module(otel_metric_reader_sup).

-behaviour(supervisor).

-export([start_link/2]).

-export([init/1]).

-define(SERVER, ?MODULE).

start_link(ProviderSup, Opts) ->
    supervisor:start_link(?MODULE, [ProviderSup, Opts]).

init([ProviderSup, Opts]) ->
    Readers = maps:get(readers, Opts, []),

    SupFlags = #{strategy => one_for_one,
                 intensity => 5,
                 period => 10},
    ChildSpecs = [begin
                      #{id => ReaderId,
                        start => {Module, start_link, [ReaderId, ProviderSup, ReaderConfig]},
                        type => worker,
                        restart => permanent,
                        shutdown => 1000}
                  end || #{id := ReaderId,
                           module := Module,
                           config := ReaderConfig} <- Readers
                 ],

    {ok, {SupFlags, ChildSpecs}}.
