%%%-------------------------------------------------------------------
%%% @author JD Bothma <jan.bothma@erlang-solutions.com>
%%% @copyright (C) 2012, Erlang Solutions Ltd.
%%% @doc Supervisor for a pool of eldap connection processes per
%%%   ejabberd vhost
%%%
%%% @end
%%% Created : 26 Sep 2012 by JD Bothma <jan.bothma@erlang-solutions.com>
%%%-------------------------------------------------------------------
-module(ejabberd_ldap_pool_sup).

-behaviour(supervisor).

%% API
-export([start_link/7]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

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
start_link(GroupPrefix, VHost, LDAPServers, Port, RootDN, RootPwd, TLSOpts) ->
    Args = [GroupPrefix, VHost, LDAPServers, Port, RootDN, RootPwd, TLSOpts],
    supervisor:start_link(?MODULE, Args).

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
init([GroupPrefix, VHost, LDAPServers, Port, RootDN, RootPwd, TLSOpts]) ->

    ejabberd_ldap_pool:start_group(GroupPrefix, VHost),

    RestartStrategy = one_for_one,
    MaxRestarts = 1000,
    MaxSecondsBetweenRestarts = 3600,

    SupFlags = {RestartStrategy, MaxRestarts, MaxSecondsBetweenRestarts},
    ChildSpecs = ejabberd_ldap_pool:child_specs(
                  GroupPrefix, VHost, LDAPServers, Port, RootDN, RootPwd, TLSOpts),
    {ok, {SupFlags, ChildSpecs}}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
