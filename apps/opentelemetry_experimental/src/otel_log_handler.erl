%%%------------------------------------------------------------------------
%% Copyright 2022-2023, OpenTelemetry Authors
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
%% @doc Specification: https://opentelemetry.io/docs/specs/otel/logs/sdk
%% @end
%%%-------------------------------------------------------------------------
-module(otel_log_handler).

-behaviour(gen_statem).

-include_lib("kernel/include/logger.hrl").

-export([start_link/1]).

%% Logger handler
-export([log/2,
         adding_handler/1,
         removing_handler/1,
         changing_config/3]).

%% gen_statem
-export([init/1,
         callback_mode/0,
         init_exporter/3,
         idle/3,
         exporting/3,
         terminate/3]).

%% OpenTelemetry specific
-export([force_flush/1]).

-export_type([config/0,
              otel_log_handler_config/0]).

-type config() :: #{id => logger:handler_id(),
                    config => otel_log_handler_config(),
                    level => logger:level() | all | none,
                    module => module(),
                    filter_default => log | stop,
                    filters => [{logger:filter_id(), logger:filter()}],
                    formatter => {module(), logger:formatter_config()}
                   }.

-type config_private() :: #{id => logger:handler_id(),
                            level => logger:level() | all | none,
                            module => module(),
                            filter_default => log | stop,
                            filters => [{logger:filter_id(), logger:filter()}],
                            formatter => {module(), logger:formatter_config()},
                            config := otel_log_handler_config(),
                            %% private fields
                            reg_name := atom(),
                            atomic_ref := atomics:atomic_ref(),
                            tables := {ets:table(), ets:table()}
                           }.

-type otel_log_handler_config() ::
        #{max_queue_size => max_queue_size(),
          exporting_timeout_ms => exporting_timeout_ms(),
          scheduled_delay_ms => scheduled_delay_ms(),
          exporter => exporter_config()}.

-type max_queue_size() :: non_neg_integer() | infinity.
-type exporter_config() :: module() | {module(), Config :: term()} | undefined.
-type exporting_timeout_ms() :: non_neg_integer().
-type scheduled_delay_ms() :: non_neg_integer().

-define(SUP, opentelemetry_experimental_sup).

-define(name_to_reg_name(Module, Id),
        list_to_atom(lists:concat([Module, "_", Id]))).
-define(table_name(_RegName_, _TabName_), list_to_atom(lists:concat([_RegName_, "_", _TabName_]))).
-define(table_1(_RegName_), ?table_name(_RegName_, table1)).
-define(table_2(_RegName_), ?table_name(_RegName_, table2)).

%% Use of atomics provides much better overload protection comparing to periodic ETS table size check.
%% It allows to enter drop mode as soon as max_queue_size is reached, while periodic table check
%% can overlook a large and fast burst of writes that can result in inserting a much larger amount of
%% log events than the configured max_queue_size.
%% Performance-wise, the cost of `atomics:get/2`, `atomics:sub_get/3` is comparable with
%% `persistent_term:get/2,3`
-define(current_tab(_AtomicRef_), atomics:get(_AtomicRef_, ?CURRENT_TAB_IX)).
-define(tab_name(_TabIx_, _Tabs_), element(_TabIx_, _Tabs_)).
-define(next_tab(_CurrentTab_), case _CurrentTab_ of
                                    ?TAB_1_IX -> ?TAB_2_IX;
                                    ?TAB_2_IX -> ?TAB_1_IX
                                end).

-define(set_current_tab(_AtomicRef_, _TabIx_), atomics:put(_AtomicRef_, ?CURRENT_TAB_IX, _TabIx_)).
-define(set_available(_AtomicRef_, _TabIx_, _Size_), atomics:put(_AtomicRef_, _TabIx_, _Size_)).
-define(get_available(_AtomicRef_, _TabIx_), atomics:get(_AtomicRef_, _TabIx_)).
-define(sub_get_available(_AtomicRef_, _TabIx_), atomics:sub_get(_AtomicRef_, _TabIx_, 1)).
-define(disable(_AtomicRef_), atomics:put(_AtomicRef_, ?CURRENT_TAB_IX, 0)).

-define(MAX_SIGNED_INT, (1 bsl 63)-1).
-define(TAB_1_IX, 1).
-define(TAB_2_IX, 2).
%% signifies which table is currently enabled (0 - disabled, 1 - table_1, 2 - table_2)
-define(CURRENT_TAB_IX, 3).

-define(private_field_err(_FieldName_), {error, {_FieldName_, "private_field_change_not_allowed"}}).
-define(change_not_allowed_err(_FieldName_), {error, {_FieldName_, "field_change_not_allowed"}}).

-define(DEFAULT_MAX_QUEUE_SIZE, 2048).
-define(DEFAULT_SCHEDULED_DELAY_MS, timer:seconds(1)).
-define(DEFAULT_EXPORTER_TIMEOUT_MS, timer:seconds(30)).
-define(DEFAULT_EXPORTER_MODULE, opentelemetry_exporter).
-define(DEFAULT_EXPORTER,
        {?DEFAULT_EXPORTER_MODULE, #{protocol => grpc, endpoints => ["http://localhost:4317"]}}).

-define(SUP_SHUTDOWN_MS, 5500).
%% Slightly lower than SUP_SHUTDOWN_MS
-define(GRACE_SHUTDOWN_MS, 5000).
-define(time_ms, erlang:monotonic_time(millisecond)).
-define(rem_time(_Timeout_, _T0_, _T1_), max(0, _Timeout_ - (_T1_ - _T0_))).

-record(data, {exporter              :: {module(), State :: term()} | undefined,
               exporter_config       :: exporter_config(),
               resource              :: otel_resource:t(),
               handed_off_table      :: ets:table() | undefined,
               runner_pid            :: pid() | undefined,
               tables                :: {ets:table(), ets:table()},
               reg_name              :: atom(),
               config                :: config_private(),
               max_queue_size        = ?DEFAULT_MAX_QUEUE_SIZE        :: non_neg_integer(),
               exporting_timeout_ms  = ?DEFAULT_EXPORTER_TIMEOUT_MS   :: exporting_timeout_ms(),
               scheduled_delay_ms    = ?DEFAULT_SCHEDULED_DELAY_MS    :: scheduled_delay_ms(),
               atomic_ref            :: atomics:atomic_ref(),
               exporter_timer        :: undefined | reference(),
               extra                 = [] %% Unused, for future extensions
              }).

start_link(#{reg_name := RegName} = Config) ->
    gen_statem:start_link({local, RegName}, ?MODULE, Config, []).

%% TODO:
%% - implement max_batch_size (it will also require changes in exporter and/or otel_otlp_logs)

%%--------------------------------------------------------------------
%% Logger handler callbacks
%%--------------------------------------------------------------------

-spec adding_handler(Config1) -> {ok, Config2} | {error, Reason} when
      Config1 :: config(),
      Config2 :: config_private(),
      Reason :: term().
adding_handler(#{id := Id}=Config) ->
    ok = start_apps(),
    RegName = ?name_to_reg_name(?MODULE, Id),
    AtomicRef = atomics:new(3, [{signed, true}]),
    Config1 = Config#{reg_name => RegName,
                      tables => {?table_1(RegName), ?table_2(RegName)},
                      atomic_ref => AtomicRef},
    OtelConfig = maps:get(config, Config, #{}),
    case validate_config(OtelConfig) of
        ok ->
            OtelConfig1 = maps:merge(default_config(), OtelConfig),
            start(Id, Config1#{config => OtelConfig1});
        Err ->
            Err
    end.

-spec changing_config(SetOrUpdate, OldConfig, NewConfig) ->
          {ok, Config} | {error, Reason} when
      SetOrUpdate :: set | update,
      OldConfig :: config_private(),
      NewConfig :: config(),
      Config :: config_private(),
      Reason :: term().
changing_config(_, #{reg_name := RegName}, #{reg_name := RegName1}) when RegName =/= RegName1 ->
    ?private_field_err(reg_name);
changing_config(_, #{atomic_ref := Ref}, #{atomic_ref := Ref1}) when Ref =/= Ref1 ->
    ?private_field_err(atomic_ref);
changing_config(_, #{tables := Tabs}, #{tables := Tabs1}) when Tabs =/= Tabs1 ->
    ?private_field_err(tables);
%% Changing timeout or exporter config requires restart/re-initialiazation of exporter,
%% which is not supported now.  If timeout or exporter needs to be changed,
%% the handler should be stopped and started with the new config
changing_config(_, #{config := #{exporter := Exporter}},
                #{config := #{exporter := Exporter1}}) when Exporter =/= Exporter1 ->
    ?change_not_allowed_err(exporter);
changing_config(_, #{config := #{exporting_timeout_ms := T}},
                #{config := #{exporting_timeout_ms := T1}}) when T =/= T1 ->
    ?change_not_allowed_err(exporting_timeout_ms);
changing_config(SetOrUpdate, #{reg_name := RegName, config := OldOtelConfig}, NewConfig) ->
    NewOtelConfig = maps:get(config, NewConfig, #{}),
    case validate_config(NewOtelConfig) of
        ok ->
            NewOtelConfig1 = case SetOrUpdate of
                                 update -> maps:merge(OldOtelConfig, NewOtelConfig);
                                 set -> maps:merge(default_config(), NewOtelConfig)
                             end,
            NewConfig1 = NewConfig#{config => NewOtelConfig1, reg_name => RegName},
            gen_statem:call(RegName, {changing_config, NewConfig1});
        Err ->
            Err
    end.

-spec removing_handler(Config) -> ok | {error, Reason} when
      Config :: config_private(), Reason :: term().
removing_handler(_Config=#{id := Id}) ->
    Res = supervisor:terminate_child(?SUP, Id),
    _ = supervisor:delete_child(?SUP, Id),
    Res.

-spec log(LogEvent, Config) -> true | dropped | {error, term()} when
      LogEvent :: logger:log_event(),
      Config :: config_private().
log(LogEvent, Config) ->
    Ts = case LogEvent of
                #{meta := #{time := Time}} -> Time;
                _ -> logger:timestamp()
            end,
    do_insert(Ts, LogEvent, Config).

-spec force_flush(config_private()) -> ok.
force_flush(#{reg_name := RegName}) ->
    gen_statem:cast(RegName, force_flush).

%%--------------------------------------------------------------------
%% gen_statem callbacks
%%--------------------------------------------------------------------

init(Config) ->
    #{config := #{exporting_timeout_ms := ExportTimeoutMs} = OtelConfig,
      atomic_ref := AtomicRef,
      reg_name := RegName,
      tables := {Tab1, Tab2}} = Config,
    process_flag(trap_exit, true),
    Resource = otel_resource_detector:get_resource(),
    ExporterConfig = maps:get(exporter, OtelConfig, ?DEFAULT_EXPORTER),
    ExporterConfig1 = exporter_conf_with_timeout(ExporterConfig, ExportTimeoutMs),

    %% assert table names match
    Tab1 = ?table_1(RegName),
    Tab2 = ?table_2(RegName),
    _Tid1 = new_export_table(Tab1),
    _Tid2 = new_export_table(Tab2),

    %% This is sligthly increased, to give the exporter runner a chance to  garcefully time-out
    %% before being killed by the handler.
    ExportTimeoutMs1 = ExportTimeoutMs + 1000,

    Data = #data{atomic_ref=AtomicRef,
                 exporter=undefined,
                 exporter_config=ExporterConfig1,
                 exporting_timeout_ms=ExportTimeoutMs1,
                 resource=Resource,
                 tables={Tab1, Tab2},
                 reg_name=RegName,
                 config = Config},
    %% Also used in change_config API, thus mutable
    Data1 = add_mutable_config_to_data(Config, Data),

    ?set_current_tab(AtomicRef, ?TAB_1_IX),
    ?set_available(AtomicRef, ?TAB_1_IX, Data1#data.max_queue_size),
    ?set_available(AtomicRef, ?TAB_2_IX, Data1#data.max_queue_size),

    {ok, init_exporter, Data1}.

callback_mode() ->
    [state_functions, state_enter].

%% TODO: handle exporter crashes and re-init it.
%% This is not expected to happen with the default grpc opentelemetry_exporter,
%% as it keeps running and retrying by itself in case of network failures.
init_exporter(enter, _OldState, _Data) ->
    {keep_state_and_data, [{state_timeout, 0, do_init_exporter}]};
init_exporter(_, do_init_exporter, Data=#data{exporter_config=ExporterConfig,
                                              atomic_ref=AtomicRef,
                                              tables=Tabs,
                                              scheduled_delay_ms=SendInterval,
                                              reg_name=RegName}) ->
    case do_init_exporter(RegName, AtomicRef, Tabs, ExporterConfig) of
        undefined ->
            {keep_state_and_data, [{state_timeout, SendInterval, do_init_exporter}]};
        Exporter ->
            TimerRef = start_exporting_timer(SendInterval),
            {next_state, idle, Data#data{exporter=Exporter, exporter_timer=TimerRef}}
    end;
init_exporter(_, _, _) ->
    %% Ignore any other, e.g, external events like force_flush in this state
    keep_state_and_data.

idle(enter, _OldState, _Data) ->
    keep_state_and_data;
idle(info, {timeout, Ref, export_logs}, Data=#data{exporter_timer=Ref}) ->
    {next_state, exporting, Data};
idle(cast, force_flush, Data) ->
    {next_state, exporting, Data};
idle(EventType, EventContent, Data) ->
    handle_event_(idle, EventType, EventContent, Data).

exporting(info, {timeout, Ref, export_logs}, #data{exporter_timer=Ref}) ->
    {keep_state_and_data, [postpone]};
exporting(enter, _OldState, Data=#data{atomic_ref=AtomicRef,
                                       tables=Tabs,
                                       max_queue_size=MaxSize,
                                       exporting_timeout_ms=ExportingTimeout,
                                       scheduled_delay_ms=SendInterval}) ->
    CurrentTab = ?current_tab(AtomicRef),
    {Data1, Actions} =
        case ?get_available(AtomicRef, CurrentTab) of
            %% No events yet, maximum available capacity, nothing to export
            MaxSize ->
                %% The other table may contain residual (late) writes not exported
                %% during the previous run. If current table is not empty, we don't
                %% need to check the size of the previous (currently disabled) table,
                %% since we will switch to it after this exporter run.
                %% However, if current table remains empty for a long time,
                %% neither export nor table switch will be triggered, and any
                %% residual late log events in the previous table would be left
                %% dangling. To avoid such cases, we check other table size
                %% and export it if it's not empty.
                maybe_export_other_table(CurrentTab, Data);
            _ ->
                RunnerPid = export_logs(CurrentTab, Data),
                {Data#data{runner_pid=RunnerPid,
                           handed_off_table=?tab_name(CurrentTab, Tabs)},
                 [{state_timeout, ExportingTimeout, exporting_timeout}]}
        end,
    {keep_state, Data1#data{exporter_timer = start_exporting_timer(SendInterval)}, Actions};
exporting(state_timeout, empty_table, Data) ->
    {next_state, idle, Data};
exporting(state_timeout, exporting_timeout, Data) ->
    %% kill current exporting process because it is taking too long
    Data1 = kill_runner(Data),
    {next_state, idle, Data1};
%% important to verify runner_pid and FromPid are the same in case it was sent
%% after kill_runner was called but before it had done the unlink
%% Exit reason is ignored, since we don't handle exporter failures specifically for now
exporting(info, {'EXIT', FromPid, _}, Data=#data{runner_pid=FromPid}) ->
    complete_exporting(Data);
exporting(EventType, Event, Data) ->
    handle_event_(exporting, EventType, Event, Data).

terminate(_Reason, State, Data=#data{exporter=Exporter,
                                     resource=Resource,
                                     config=Config,
                                     atomic_ref=AtomicRef,
                                     tables={Tab1, Tab2}
                                    }) ->
    ?disable(AtomicRef),
    T0 = ?time_ms,
    _ = maybe_wait_for_current_runner(State, Data, ?GRACE_SHUTDOWN_MS),
    T1 = ?time_ms,

    %% Check both tables as each one may have some late unexported log events.
    %% NOTE: exports are attempted sequentially to follow the specification restriction:
    %% "Export will never be called concurrently for the same exporter instance"
    %% (see: https://opentelemetry.io/docs/specs/otel/logs/sdk/#export).
    RemTime = ?rem_time(?GRACE_SHUTDOWN_MS, T0, T1),
    ets:info(Tab1, size) > 0
        andalso export_and_wait(Exporter, Resource, Tab1, Config, RemTime),
    T2 = ?time_ms,
    RemTime1 = ?rem_time(RemTime, T1, T2),
    ets:info(Tab2, size) > 0
        andalso export_and_wait(Exporter, Resource, Tab2, Config, RemTime1),

    _ = otel_exporter:shutdown(Exporter),
    ok.

%%--------------------------------------------------------------------
%% Internal functions
%%--------------------------------------------------------------------

start_apps() ->
    _ = application:ensure_all_started(opentelemetry_exporter),
    _ = application:ensure_all_started(opentelemetry_experimental),
    ok.

start(Id, Config) ->
    ChildSpec =
        #{id       => Id,
          start    => {?MODULE, start_link, [Config]},
          %% The handler must be stopped gracefully by calling `logger:remove_handler/1`,
          %% which calls `supervisor:terminate_child/2` (in `removing_handler/2` cb).
          %% Any other termination is abnormal and deserves a restart.
          restart  => permanent,
          shutdown => ?SUP_SHUTDOWN_MS,
          type     => worker,
          modules  => [?MODULE]},
    case supervisor:start_child(?SUP, ChildSpec) of
        {ok, _Pid} ->
            {ok, Config};
        {error, {Reason, Ch}} when is_tuple(Ch), element(1, Ch) == child ->
            {error, Reason};
        {error, _Reason}=Error ->
            Error
    end.

handle_event_(_State, {call, From}, {changing_config, NewConfig}, Data) ->
    {keep_state, add_mutable_config_to_data(NewConfig, Data), [{reply, From, {ok, NewConfig}}]};
handle_event_(_State, info, {'EXIT', Pid, Reason}, #data{runner_pid=RunnerPid})
  when Pid =/= RunnerPid ->
    %% This can be a linked exporter process, unless someone linked to the handler process,
    %% or explicitly called exit(HandlerPid, Reason)
    %% This will call terminate/3 and may try to export current log events,
    %% even if the linked exporter process is down.
    %% This is safe, though, as all errors of otel_exporter:export_logs/4 are caught.
    {stop, Reason};
handle_event_(_State, _, _, _) ->
    keep_state_and_data.

do_init_exporter(RegName, AtomicRef, Tabs, ExporterConfig) ->
    case otel_exporter:init(logs, RegName, ExporterConfig) of
        Exporter when Exporter =/= undefined andalso Exporter =/= none ->
            %% Need to enable log writes, if it has been disabled previously
            ?set_current_tab(AtomicRef, ?TAB_1_IX),
            Exporter;
        _ ->
            %% exporter is undefined/none
            %% disable the insertion of new log events and delete the current table
            clear_table_and_disable(AtomicRef, Tabs),
            undefined
    end.

start_exporting_timer(SendInterval) ->
    erlang:start_timer(SendInterval, self(), export_logs).

maybe_export_other_table(CurrentTab, Data=#data{tables=Tabs,
                                                exporting_timeout_ms=ExportingTimeout}) ->
    NextTab = ?next_tab(CurrentTab),
    %% Check ETS size instead of the counter, as late writes can't be detected with the atomic counter
    case ets:info(?tab_name(NextTab, Tabs), size) of
        0 ->
            %% in an `enter' handler we can't return a `next_state' or `next_event'
            %% so we rely on a timeout to trigger the transition to `idle'
            {Data#data{runner_pid=undefined}, [{state_timeout, 0, empty_table}]};
        _ ->
            RunnerPid = export_logs(NextTab, Data),
            {Data#data{runner_pid=RunnerPid, handed_off_table=?tab_name(CurrentTab, Tabs)},
             [{state_timeout, ExportingTimeout, exporting_timeout}]}
    end.

export_logs(CurrentTab, #data{exporter=Exporter,
                              max_queue_size=MaxSize,
                              resource=Resource,
                              atomic_ref=AtomicRef,
                              tables=Tabs,
                              config=Config}) ->

    NewCurrentTab = ?next_tab(CurrentTab),
    %% the new table is expected to be empty or hold a few late writes from the previous export,
    %% so it safe to set available max size
    ?set_available(AtomicRef, NewCurrentTab, MaxSize),
    ?set_current_tab(AtomicRef, NewCurrentTab),
    export_async(Exporter, Resource, ?tab_name(CurrentTab, Tabs), Config).

export_async(Exporter, Resource, CurrentTab, Config) ->
    erlang:spawn_link(fun() -> export(Exporter, Resource, CurrentTab, Config) end).

export(undefined, _, _, _) ->
    true;
export({ExporterModule, ExporterState}, Resource, Tab, Config) ->
    try
        %% we ignore values, as no retries mechanism, is implemented
        otel_exporter:export_logs(ExporterModule, {Tab, Config}, Resource, ExporterState)
    catch
        Class:Reason:St ->
            %% Other logger handler(s) (e.g. default) should be enabled, so that
            %% log events produced by otel_log_handler are not lost in case otel_log_handler
            %% is not functioning properly.
            ?LOG_ERROR("logs exporter ~p failed with exception: ~p:~p, stacktrace: ~p",
                       [Class, Reason, otel_utils:stack_without_args(St)]),
            error
    end.

new_export_table(Name) ->
    %% log event timestamps used as keys are not guaranteed to always be unique,
    %% so we use duplicate_bag
    %% Using timestamps as keys instead of instrumentation scopes is expected
    %% to have higher entropy which should improve write concurrency
    ets:new(Name, [public,
                   named_table,
                   {write_concurrency, true},
                   duplicate_bag]).

do_insert(Ts, LogEvent, #{atomic_ref := AtomicRef, tables := Tabs} = Config) ->
    try
        case ?current_tab(AtomicRef) of
            0 -> dropped;
            CurrentTab ->
                case ?sub_get_available(AtomicRef, CurrentTab) of
                    Seq when Seq > 0 ->
                        ets:insert(?tab_name(CurrentTab, Tabs), {Ts, LogEvent});
                    0 ->
                        %% max_queue_size is reached
                        Res = ets:insert(?tab_name(CurrentTab, Tabs), {Ts, LogEvent}),
                        _ = force_flush(Config),
                        Res;
                    _ ->
                        dropped
                end
        end
    catch
        error:badarg ->
            {error, no_otel_log_handler};
        Err:Reason ->
            {error, {Err, Reason}}
    end.

clear_table_and_disable(AtomicRef, Tabs) ->
    case ?current_tab(AtomicRef) of
        0 ->
            %% already disabled
            ok;
        CurrentTab ->
            ?disable(AtomicRef),
            CurrentTabName = ?tab_name(CurrentTab, Tabs),
            ets:delete_all_objects(CurrentTabName),
            ok
    end.

complete_exporting(Data) ->
    {next_state, idle, Data#data{runner_pid=undefined,
                                 handed_off_table=undefined}}.

kill_runner(Data=#data{runner_pid=RunnerPid, handed_off_table=Tab}) when RunnerPid =/= undefined ->
    Mon = erlang:monitor(process, RunnerPid),
    erlang:unlink(RunnerPid),
    erlang:exit(RunnerPid, kill),
    %% NOTE: this is not absolutely necessary anymore, as we don't delete/recreate tables
    receive
        {'DOWN', Mon, process, RunnerPid, _} ->
            %% NOTE: if the runner was killed even before it managed to take all or
            %% at least significant amount of records from the table and
            %% exporter timeouts keep occurring on and on, there is a risk of continuous
            %% table size growth. This situation has a low probability,
            %% especially when the configuration is meaningful, e.g., max_queue_size is not
            %% enormously large and exporting_timeout is not very small.
            %% The table is cleared as a safety measure to eliminate the risk of the above case.
            %% This should probably be optional and configurable.
            _ = ets:delete_all_objects(Tab),
            Data#data{runner_pid=undefined, handed_off_table=undefined}
    end.

exporter_conf_with_timeout({?DEFAULT_EXPORTER_MODULE, Conf}, TimeoutMs) ->
    {?DEFAULT_EXPORTER_MODULE, Conf#{timeout_ms => TimeoutMs}};
exporter_conf_with_timeout(OtherExporter, _Timeout) ->
    OtherExporter.

%% terminate/3 helpers

export_and_wait(Exporter, Resource, Tab, Config, Timeout) ->
    RunnerPid = export_async(Exporter, Resource, Tab, Config),
    wait_for_runner(RunnerPid, Timeout).

wait_for_runner(RunnerPid, Timeout) ->
    receive
        {'EXIT', RunnerPid, _} -> ok
    after Timeout ->
            erlang:exit(RunnerPid, kill),
            ok
    end.

maybe_wait_for_current_runner(exporting, #data{runner_pid=RunnerPid}, Timeout) when is_pid(RunnerPid) ->
    wait_for_runner(RunnerPid, Timeout);
maybe_wait_for_current_runner(_State, _Date, _Timeout) -> ok.

%% Config helpers

default_config() ->
    %% exporter is set separately because it's not allowed to be changed for now (requires handler restart)
    #{max_queue_size => ?DEFAULT_MAX_QUEUE_SIZE,
      exporting_timeout_ms => ?DEFAULT_EXPORTER_TIMEOUT_MS,
      scheduled_delay_ms => ?DEFAULT_SCHEDULED_DELAY_MS}.

validate_config(Config) ->
    Errs = maps:fold(fun(K, Val, Acc) ->
                             case validate_opt(K, Val, Config) of
                                 ok -> Acc;
                                 Err -> [Err | Acc]
                             end
              end,
                     [], Config),
    case Errs of
        [] -> ok;
        _ -> {error, Errs}
    end.

validate_opt(max_queue_size, infinity, _Config) ->
    ok;
validate_opt(K, Val, _Config) when is_integer(Val), Val > 0,
                          K =:= max_queue_size;
                          K =:= exporting_timeout_ms;
                          K =:= scheduled_delay_ms->
    ok;
validate_opt(exporter, {Module, _}, _Config) when is_atom(Module) ->
    ok;
validate_opt(exporter, Module, _Config) when is_atom(Module) ->
    ok;
validate_opt(K, Val, _Config) ->
    {invalid_config, K, Val}.

add_mutable_config_to_data(#{config := OtelConfig} = Config, Data) ->
    #{max_queue_size:=SizeLimit,
      scheduled_delay_ms:=ScheduledDelay
     } = OtelConfig,
    SizeLimit1 = case SizeLimit of
                     %% high enough, must be infeasible to reach
                     infinity -> ?MAX_SIGNED_INT;
                     Int  -> Int
                 end,
    Data#data{config=Config,
              max_queue_size=SizeLimit1,
              scheduled_delay_ms=ScheduledDelay}.
