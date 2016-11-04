%%--------------------------------------------------------------------
%% Copyright (c) 2015-2016 Feng Lee <feng@emqtt.io>.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%--------------------------------------------------------------------

-module(emqttd_plugin_lcy).

-include("emqttd_lcy.hrl").
-include_lib("../../../include/emqttd.hrl").

-export([load/1, unload/0]).
-import(emqttd_acl,[parse_query/1]).

%% Hooks functions

-export([on_client_connected/3, on_client_disconnected/3]).
%%-export([on_client_subscribe/4, on_client_unsubscribe/4]).
%%-export([on_session_created/3, on_session_subscribed/4, on_session_unsubscribed/4, on_session_terminated/4]).
%%-export([on_message_publish/2, on_message_delivered/4, on_message_acked/4]).
-export([on_message_publish/2]).
-export([on_message_delivered/4]).
-export([start_time/1,publish_time/0,cancel/1]).

%% Called when the plugin application start
load(Env) ->
    %%emqttd:hook('client.connected', fun ?MODULE:on_client_connected/3, [Env]),
    emqttd:hook('client.disconnected', fun ?MODULE:on_client_disconnected/3, [Env]),
    %%emqttd:hook('client.subscribe', fun ?MODULE:on_client_subscribe/4, [Env]),
    %%emqttd:hook('client.unsubscribe', fun ?MODULE:on_client_unsubscribe/4, [Env]),
    %%emqttd:hook('session.created', fun ?MODULE:on_session_created/3, [Env]),
    %%emqttd:hook('session.subscribed', fun ?MODULE:on_session_subscribed/4, [Env]),
    %%emqttd:hook('session.unsubscribed', fun ?MODULE:on_session_unsubscribed/4, [Env]),
    %%emqttd:hook('session.terminated', fun ?MODULE:on_session_terminated/4, [Env]),
    if_cmd_enabled(authcmd,fun(AuthCmd) ->
        SuperCmd = application:get_env(?APP,supercmd,undefined),
        {ok,PassHash} = application:get_env(?APP,password_hash),
        emqttd_access_control:register_mod(auth,emqttd_auth,{AuthCmd,SuperCmd,PassHash})
    end),

    if_enabled(aclquery,fun(AclQuery) ->
        io:format("starting acl mod~n"),
        {ok,AclNomatch} = application:get_env(?APP,acl_nomatch),
        {ok,GetUUID} = application:get_env(?APP,getuuid),
        ok = emqttd_access_control:register_mod(acl,emqttd_acl,{AclQuery,AclNomatch,GetUUID})
    end),
    
    
    InterVal = application:get_env(?APP,time_interval,60000),
    spawn(fun() -> start_time(InterVal) end),
    emqttd:hook('message.delivered', fun ?MODULE:on_message_delivered/4, [Env]),
    emqttd:hook('message.publish', fun ?MODULE:on_message_publish/2, [Env]).
    %%emqttd:hook('message.acked', fun ?MODULE:on_message_acked/4, [Env]).
%%
%%
cancel(Pid) -> Pid ! canecel.

start_time(Time)->
    receive 
        cancel ->
            void
    after Time ->
              publish_time(),
              start_time(Time)
              %%start_time(Time,Fun)
    end.

publish_time() ->
    ClientId = <<"localhost">>,
    %%Qos = 0,
    %%Retain = 0,
    Topic = <<"/SYS/SrvTime">>,
    Payload = list_to_binary(strftime(os:timestamp())),
    Msg = emqttd_message:make(ClientId,Topic,Payload),
    emqttd:publish(Msg).
    %%emqttd:publish(emqttd_message:set_flag(sys,Msg)).

strftime({MegaSecs, Secs, _MicroSecs}) ->
    strftime(datetime(MegaSecs * 1000000 + Secs));

strftime({{Y,M,D}, {H,MM,S}}) ->
    W = calendar:day_of_the_week(Y,M,D),
    lists:flatten(
        io_lib:format(
            "~4..0w-~2..0w-~2..0w ~1..0w ~2..0w:~2..0w:~2..0w", [Y, M, D, W, H, MM, S])).

datetime(Timestamp) when is_integer(Timestamp) ->
    Universal = calendar:gregorian_seconds_to_datetime(Timestamp +
    calendar:datetime_to_gregorian_seconds({{1970,1,1}, {0,0,0}})),
    calendar:universal_time_to_local_time(Universal).

on_client_connected(ConnAck, Client = #mqtt_client{client_id = ClientId}, _Env) ->
    %%io:format("client ~s connected, connack: ~w~n", [ClientId, ConnAck]),
    ClientId,
    ConnAck,
    {ok, Client}.

on_client_disconnected(Reason, _Client = #mqtt_client{client_id = ClientId}, _Env) ->
    Reason,
    ClientId,
    %%io:format("client ~s disconnected, reason: ~w~n", [ClientId, Reason]),
    ok.

%%on_client_subscribe(ClientId, Username, TopicTable, _Env) ->
%%    io:format("client(~s/~s) will subscribe: ~p~n", [Username, ClientId, TopicTable]),
%%    {ok, TopicTable}.
%%    
%%on_client_unsubscribe(ClientId, Username, TopicTable, _Env) ->
%%    io:format("client(~s/~s) unsubscribe ~p~n", [ClientId, Username, TopicTable]),
%%    {ok, TopicTable}.
%%
%%on_session_created(ClientId, Username, _Env) ->
%%    io:format("session(~s/~s) created.", [ClientId, Username]).
%%
%%on_session_subscribed(ClientId, Username, {Topic, Opts}, _Env) ->
%%    io:format("session(~s/~s) subscribed: ~p~n", [Username, ClientId, {Topic, Opts}]),
%%    {ok, {Topic, Opts}}.
%%
%%on_session_unsubscribed(ClientId, Username, {Topic, Opts}, _Env) ->
%%    io:format("session(~s/~s) unsubscribed: ~p~n", [Username, ClientId, {Topic, Opts}]),
%%    ok.
%%
%%on_session_terminated(ClientId, Username, Reason, _Env) ->
%%    io:format("session(~s/~s) terminated: ~p.", [ClientId, Username, Reason]).
%%
%%%% transform message and return
on_message_publish(Message = #mqtt_message{topic = <<"#", _/binary>>}, _Env) ->
    Message,
    ok;
    %%{ok, Message};

on_message_publish(Message, _Env) ->
    %%io:format("publish ~s~n", [emqttd_message:format(Message)]),
    %%{ok, Message}.
    Message,
    ok.

on_message_delivered(ClientId, Username, Message, _Env) ->
    %%io:format("delivered to client(~s/~s): ~s~n", [Username, ClientId, emqttd_message:format(Message)]),
    Username,ClientId,Message,
    {ok, Message}.

%%on_message_acked(ClientId, Username, Message, _Env) ->
%%    io:format("client(~s/~s) acked: ~s~n", [Username, ClientId, emqttd_message:format(Message)]),
%%    {ok, Message}.

%% Called when the plugin application stop
unload() ->
    emqttd:unhook('client.connected', fun ?MODULE:on_client_connected/3),
    emqttd:unhook('client.disconnected', fun ?MODULE:on_client_disconnected/3),
    %%emqttd:unhook('client.subscribe', fun ?MODULE:on_client_subscribe/4),
    %%emqttd:unhook('client.unsubscribe', fun ?MODULE:on_client_unsubscribe/4),
    %%emqttd:unhook('session.subscribed', fun ?MODULE:on_session_subscribed/4),
    %%emqttd:unhook('session.unsubscribed', fun ?MODULE:on_session_unsubscribed/4),
    emqttd:unhook('message.delivered', fun ?MODULE:on_message_delivered/4),
    emqttd:unhook('message.publish', fun ?MODULE:on_message_publish/2).
    %%emqttd:unhook('message.acked', fun ?MODULE:on_message_acked/4).


if_cmd_enabled(Name, Fun) ->
    case application:get_env(?APP, Name) of
        {ok, Cmd} -> Fun(Cmd);
        undefined -> ok
    end.

if_enabled(Cfg, Fun) ->
    case application:get_env(?APP, Cfg) of
        {ok, Query} -> Fun(parse_query(Query));
        undefined   -> ok
end.


