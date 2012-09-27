%%%-------------------------------------------------------------------
%%% @author JD Bothma <jan.bothma@erlang-solutions.com>
%%% @copyright (C) 2012, Erlang Solutions Ltd.
%%% @doc Top supervisor for ejabberd_auth_ldap for a particular vhost
%%%
%%% @end
%%% Created : 25 Sep 2012 by JD Bothma <jan.bothma@erlang-solutions.com>
%%%-------------------------------------------------------------------
-module(ejabberd_auth_ldap_sup).

-behaviour(supervisor).

%% API
-export([start_link/0,
         add_conf_server/1,
         add_pool_sup/1]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).
-define(POOL_SUP, ejabberd_auth_ldap_pool_sup).
-define(CONF_SERV, ejabberd_auth_ldap).

%%%===================================================================
%%% API functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the supervisor
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

add_conf_server(VHost) ->
    Id = gen_mod:get_module_proc(VHost, ?CONF_SERV),
    ChildSpec = {Id, {?CONF_SERV, start_link, [VHost]},
                 transient, 1000, worker, [?CONF_SERV]},
    supervisor:start_child(?MODULE, ChildSpec).

add_pool_sup(VHost) ->
    Id = gen_mod:get_module_proc(VHost, ?POOL_SUP),
    ChildSpec = {Id, {?POOL_SUP, start_link, [VHost]},
                 transient, 1000, supervisor, [?POOL_SUP]},
    supervisor:start_child(?MODULE, ChildSpec).

%%%===================================================================
%%% Supervisor callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a supervisor is started using supervisor:start_link/[2,3],
%% this function is called by the new process to find out about
%% restart strategy, maximum restart frequency and child
%% specifications.
%%
%% @spec init(Args) -> {ok, {SupFlags, [ChildSpec]}} |
%%                     ignore |
%%                     {error, Reason}
%% @end
%%--------------------------------------------------------------------
init([]) ->
    RestartStrategy = one_for_one,
    MaxRestarts = 1000,
    MaxSecondsBetweenRestarts = 3600,

    SupFlags = {RestartStrategy, MaxRestarts, MaxSecondsBetweenRestarts},

    {ok, {SupFlags, []}}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
