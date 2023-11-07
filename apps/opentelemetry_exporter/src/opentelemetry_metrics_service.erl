%%%-------------------------------------------------------------------
%% @doc Client module for grpc service opentelemetry.proto.collector.metrics.v1.MetricsService.
%% @end
%%%-------------------------------------------------------------------

%% this module was generated and should not be modified manually

-module(opentelemetry_metrics_service).

-compile(export_all).
-compile(nowarn_export_all).

-include_lib("grpc/include/grpc.hrl").

-define(SERVICE, 'opentelemetry.proto.collector.metrics.v1.MetricsService').
-define(PROTO_MODULE, 'opentelemetry_exporter_metrics_service_pb').
-define(MARSHAL(T), fun(I) -> ?PROTO_MODULE:encode_msg(I, T) end).
-define(UNMARSHAL(T), fun(I) -> ?PROTO_MODULE:decode_msg(I, T) end).
-define(DEF(Path, Req, Resp, MessageType),
        #{path => Path,
          service =>?SERVICE,
          message_type => MessageType,
          marshal => ?MARSHAL(Req),
          unmarshal => ?UNMARSHAL(Resp)}).

-spec export(opentelemetry_exporter_metrics_service_pb:export_metrics_service_request())
    -> {ok, opentelemetry_exporter_metrics_service_pb:export_metrics_service_response(), grpc:metadata()}
     | {error, term()}.
export(Req) ->
    export(Req, #{}, #{}).

-spec export(opentelemetry_exporter_metrics_service_pb:export_metrics_service_request(), grpc:options())
    -> {ok, opentelemetry_exporter_metrics_service_pb:export_metrics_service_response(), grpc:metadata()}
     | {error, term()}.
export(Req, Options) ->
    export(Req, #{}, Options).

-spec export(opentelemetry_exporter_metrics_service_pb:export_metrics_service_request(), grpc:metadata(), grpc_client:options())
    -> {ok, opentelemetry_exporter_metrics_service_pb:export_metrics_service_response(), grpc:metadata()}
     | {error, term()}.
export(Req, Metadata, Options) ->
    grpc_client:unary(?DEF(<<"/opentelemetry.proto.collector.metrics.v1.MetricsService/Export">>,
                           export_metrics_service_request, export_metrics_service_response, <<"opentelemetry.proto.collector.metrics.v1.ExportMetricsServiceRequest">>),
                      Req, Metadata, Options).

