%%%-------------------------------------------------------------------
%%% @author JD Bothma <jan.bothma@erlang-solutions.com>
%%% @copyright (C) 2012, Erlang Solutions Ltd
%%% @doc A supervisor for a mod_vcard_ldap.
%%%
%%% One such supervisor is added to ejabberd_sup for each vhost that has
%%% a mod_vcard_ldap. Its job is to supervise the mod_vcard_ldap gen_server
%%% and corresponding ejabberd_ldap_pool_sup.
%%%
%%% It is the mod_vcard_ldap that adds the ejabberd_ldap_pool_sup to its
%%% supervisor.
%%%
%%% @end
%%% Created : 16 Oct 2012 by JD Bothma <jan.bothma@erlang-solutions.com>
%%%-------------------------------------------------------------------
-module(mod_vcard_ldap_sup).

-behaviour(supervisor).

%% API
-export([start_link/3]).

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
start_link(SupName, Host, Opts) ->
    supervisor:start_link({local, SupName}, ?MODULE, [Host, Opts]).

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
init([Host, Opts]) ->
    RestartStrategy = rest_for_one,
    MaxRestarts = 1000,
    MaxSecondsBetweenRestarts = 3600,

    SupFlags = {RestartStrategy, MaxRestarts, MaxSecondsBetweenRestarts},

    Restart = permanent,
    Shutdown = 2000,
    Type = worker,

    ConfigChild = {mod_vcard_ldap,
                   {mod_vcard_ldap, start_link, [Host, Opts]},
                   Restart, Shutdown, Type, [mod_vcard_ldap]},

    {ok, {SupFlags, [ConfigChild]}}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
